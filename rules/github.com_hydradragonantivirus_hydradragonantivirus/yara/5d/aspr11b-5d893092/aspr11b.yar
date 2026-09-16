rule aspr11b
{
	meta:
		author = "PEiD"
		description = "ASProtect 1.1b MTE -> Alexey Solodovnikov"
		group = "106"
		function = "3"
	strings:
		$a0 = { 60 E9 ?? 04 }
	condition:
		$a0
}