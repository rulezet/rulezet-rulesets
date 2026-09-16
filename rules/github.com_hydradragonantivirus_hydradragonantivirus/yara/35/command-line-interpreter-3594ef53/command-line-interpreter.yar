rule Command_Line_Interpreter {
 	meta:
		mitre = "T1059 Command and Scripting Interpreter"
 	strings:
		$s1 = "/usr/bin"
		$s2 = "bash"
		$s3 = "zsh"
       		$aa = "osascript"
		$ab = "/usr/bin/osascript"
		$ac = "display dialog"
		$ad = "tell app"
		$ae = "bash -c"
		$ae0 = "bash -i"
		$ae1 = "/bin/bash"
		$ae2 = "bash" fullword
		$af = "eval" fullword
		$ag = "os.popen"
		$az = "zsh -c"
       		$aA = "osascript" base64
		$aB = "/usr/bin/osascript" base64
		$aB1 = "/usr/bin" base64
		$aC = "display dialog" base64
		$aD = "tell app" base64
		$aE = "bash -c" base64
		$aE0 = "bash -i" base64
		$aE1 = "/bin/bash" base64
		$aE2 = "bash" base64
		$aF = "eval" base64
		$aG = "os.popen" base64
   	condition:
 		 2 of ($s*) or any of ($a*)
}