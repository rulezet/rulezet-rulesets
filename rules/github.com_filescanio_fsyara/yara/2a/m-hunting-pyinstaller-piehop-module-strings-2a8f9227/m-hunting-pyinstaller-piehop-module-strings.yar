rule M_Hunting_PyInstaller_PIEHOP_Module_Strings : hardened
{
	meta:
		author = "Mandiant"
		date = "2023-04-11"
		description = "Searching for PyInstaller files with a custom Python script/module associated with PIEHOP."
		source = "https://cloud.google.com/blog/topics/threat-intelligence/cosmicenergy-ot-malware-russian-response/"
		score = 60

	strings:
		$lib = {69 65 63 31 30 34 5f 6d 73 73 71 6c 5f 6c 69 62}

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and $lib
}