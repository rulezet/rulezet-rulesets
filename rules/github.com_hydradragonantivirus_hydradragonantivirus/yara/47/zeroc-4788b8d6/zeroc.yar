rule zeroc
{
	meta:
		author = "PEiD"
		description = "PE-Crypter -> Zero Coder"
		group = "197"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D EB 26 }
	condition:
		$a0
}