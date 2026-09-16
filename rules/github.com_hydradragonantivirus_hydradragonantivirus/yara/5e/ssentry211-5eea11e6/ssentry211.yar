rule ssentry211
{
	meta:
		author = "PEiD"
		description = "SoftSentry 2.11 -> 20/20 Software"
		group = "170"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 E9 50 }
	condition:
		$a0
}