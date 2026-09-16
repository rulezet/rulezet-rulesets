rule fsgcrypt
{
	meta:
		author = "PEiD"
		description = "FSG Crypt 0.1 (Private) -> EMBRACE"
		group = "123"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? B9 0B 00 00 00 80 34 08 ?? E2 }
	condition:
		$a0
}