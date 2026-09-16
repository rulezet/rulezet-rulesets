rule Reflective_Code_Loading {
 	meta:
		mitre = "T1620 Reflective Code Loading"
 	strings:
       		$a = "execv"
                $as = "NSAppleScript"
		$ase = "executeAndReturnError"
		$b = "fork"
		$n = "NSTask"
		$p = "NSPipe"
       		$A = "execv" base64
                $AS = "NSAppleScript" base64
		$ASE = "executeAndReturnError" base64
		$B = "fork" base64
		$N = "NSTask" base64
		$P = "NSPipe" base64
   	condition:
 		any of them
}