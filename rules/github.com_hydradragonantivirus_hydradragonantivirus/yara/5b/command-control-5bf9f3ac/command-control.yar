rule Command_Control {
 	meta:
		mitre = "TA0010, TA0011, T1048: Command and Control, Exfiltration"
 	strings:
		$z = "curl" fullword
       		$a = "curl -ks"
		$b = "curl -fsL"
		$c = "curl -s -L"
		$d = "curl -L -f"
		$e = "curl --connect-timeout"
		$f = "curl --retry"
		$u = "/usr/bin/curl"
       		$A = "curl -ks" base64
		$B = "curl -fsL" base64
		$C = "curl -s -L" base64
		$D = "curl -L -f" base64
		$E = "curl --connect-timeout" base64
		$F = "curl --retry" base64
		$U = "/usr/bin/curl" base64
   	condition:
 		any of them
}