rule Persistence {
        meta:
                mitre = "T1053, T1543, T1569 Create or Modify System Process, TA0003 Persistence"		
 	strings:
       		$a = "crontab"
		$b = "LaunchAgents"
		$c = "LaunchDaemons"
		$d = "periodic"
		$e = "Login Items"
		$f = "launchctl load"
		$g = "launchctl start"
       		$A = "crontab" base64
		$B = "LaunchAgents" base64 
		$C = "LaunchDaemons" base64
		$D = "periodic" base64
		$E = "Login Items" base64
		$F = "launchctl load" base64
		$G = "launchctl start" base64
   	condition:
 		any of them
}