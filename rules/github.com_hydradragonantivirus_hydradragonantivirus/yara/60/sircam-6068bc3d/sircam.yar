rule sircam
{
	meta:
		author = "PEiD"
		description = "WARNING -> VIRUS -> W32@Sircam_mm"
		group = "800"
		function = "0"
	strings:
		$a0 = { 55 8B EC B9 41 ?? ?? ?? 6A ?? 6A ?? 49 75 F9 51 53 56 57 B8 D4 A8 41 ?? E8 BF B0 FE FF BE }
	condition:
		$a0
}