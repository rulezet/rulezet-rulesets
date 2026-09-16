rule istub32_gbls
{
	meta:
		author = "PEiD"
		description = "GLBS Install Stub 32-bit -> Wise"
		group = "306"
		function = "12"
	strings:
		$a0 = { 55 8B EC 81 EC ?? ?? ?? ?? 53 56 }
	condition:
		$a0
}