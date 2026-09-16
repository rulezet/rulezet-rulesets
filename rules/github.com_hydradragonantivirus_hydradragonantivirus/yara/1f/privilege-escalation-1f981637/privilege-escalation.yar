rule Privilege_Escalation {
	meta:
		mitre = ""
 	strings:
       		$a = "with administrator privileges"
		$b = "sudo" fullword 
		$b0 = "sudo -S" 		$b1 = "sudoers"
		$c = "with hidden answer"
       		$A = "with administrator privileges" base64
		$B = "sudo" base64
		$B0 = "sudo -S" base64 		$B1 = "sudoers" base64
		$C = "with hidden answer" base64
   	condition:
 		any of them 
}