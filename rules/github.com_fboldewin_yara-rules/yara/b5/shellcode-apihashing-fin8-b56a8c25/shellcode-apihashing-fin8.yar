rule Shellcode_APIHashing_FIN8 {
	meta:
		description = "Detects FIN8 Shellcode APIHashing"
		author = "Frank Boldewin (@r3c0nst)"
		date = "2021-03-16"
		reference = "https://www.bitdefender.com/files/News/CaseStudies/study/394/Bitdefender-PR-Whitepaper-BADHATCH-creat5237-en-EN.pdf"

	strings:
		$APIHashing32bit1 = {68 F2 55 03 88 68 65 19 6D 1E} 
		$APIHashing32bit2 = {68 9B 59 27 21 C1 E9 17 33 4C 24 10 68 37 5C 32 F4} 
		
		$APIHashing64bit = {49 BF 65 19 6D 1E F2 55 03 88 49 BE 37 5C 32 F4 9B 59 27 21} 
		
	condition:
		all of ($APIHashing32bit*) or $APIHashing64bit

     
}