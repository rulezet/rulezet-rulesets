rule ep1
{
	meta:
		author = "PEiD"
		description = "EP 1.0 -> CoDe_Inside"
		group = "117"
		function = "0"
	strings:
		$a0 = { 50 83 C0 17 8B F0 97 33 C0 33 C9 B1 24 AC }
	condition:
		$a0
}