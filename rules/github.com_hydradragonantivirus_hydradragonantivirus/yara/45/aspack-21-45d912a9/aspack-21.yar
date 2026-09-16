rule aspack_21
{
	meta:
		author = "PEiD"
		description = "ASPack 2.1 -> Alexey Solodovnikov"
		group = "105"
		function = "0"
	strings:
		$a0 = { 60 E8 72 05 ?? ?? EB 33 87 DB 90 }
	condition:
		$a0
}