rule aspr12x
{
	meta:
		author = "PEiD"
		description = "ASProtect 1.2x -> Alexey Solodovnikov"
		group = "106"
		function = "3"
	strings:
		$a0 = { ?? ?? 68 01 ?? ?? ?? C3 AA }
	condition:
		$a0
}