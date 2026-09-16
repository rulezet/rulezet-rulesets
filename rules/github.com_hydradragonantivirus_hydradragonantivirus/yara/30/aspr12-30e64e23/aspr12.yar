rule aspr12
{
	meta:
		author = "PEiD"
		description = "ASProtect 1.2 -> Alexey Solodovnikov"
		group = "106"
		function = "3"
	strings:
		$a0 = { 68 01 ?? ?? ?? C3 }
	condition:
		$a0
}