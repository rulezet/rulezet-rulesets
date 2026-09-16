rule File_Deletion {
 	meta:
		mitre = "T1070.004 File Deletion"
 	strings:
       		$a = "_rmdir"
		$b = "rm -rf"
		$c = "/bin/rm"
       		$A = "_rmdir" base64
		$B = "rm -rf" base64
		$C = "/bin/rm" base64
   	condition:
 		any of them
}