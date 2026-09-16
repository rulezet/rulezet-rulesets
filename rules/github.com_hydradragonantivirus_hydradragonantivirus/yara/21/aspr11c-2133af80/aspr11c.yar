rule aspr11c
{
	meta:
		author = "PEiD"
		description = "ASProtect 1.1c MTE -> Alexey Solodovnikov"
		group = "106"
		function = "3"
	strings:
		$a0 = { 60 E8 1B ?? ?? ?? E9 FC }
	condition:
		$a0
}