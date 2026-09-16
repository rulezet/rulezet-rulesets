rule aspack_211d
{
	meta:
		author = "PEiD"
		description = "ASPack 2.11d -> Alexey Solodovnikov"
		group = "100"
		function = "0"
	strings:
		$a0 = { 60 E8 02 ?? ?? ?? EB 09 5D 55 }
	condition:
		$a0
}