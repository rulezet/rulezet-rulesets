rule Evasion {
        meta:
	        mitre = "T1562 Disable or Modify Tools"
 	strings:
       		$a = "killall" 
		$b = "kill -9"
		$c = "pkill" 
		$d = "sleep"
		$e = "sleepForTimeInterval"
                $i = "debug" nocase
		$w = "waitpid"
       		$A = "killall" base64
		$B = "kill -9" base64
		$C = "pkill" base64
		$D = "sleep" base64
		$E = "sleepForTimeInterval" base64
                $I = "debug" base64
		$W = "waitpid" base64

   	condition:
 		any of them
}