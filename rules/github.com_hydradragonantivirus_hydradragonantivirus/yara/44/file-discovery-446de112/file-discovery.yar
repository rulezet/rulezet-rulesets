rule File_Discovery {
 	meta:
		mitre = "T1083 File and Directory Discovery"
 	strings:
       		$a = "dirname"
		$b = "basename"
		$A = "dirname" base64
		$B = "basename" base64
   	condition:
 		any of them
}