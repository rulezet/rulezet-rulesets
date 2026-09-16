rule pen31
{
	meta:
		author = "PEiD"
		description = "PEncrypt 3.1 -> junkcode"
		group = "142"
		function = "0"
	strings:
		$a0 = { E9 ?? ?? ?? ?? F0 0F C6 }
	condition:
		$a0
}