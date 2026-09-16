rule _Hardlock_dongle_Alladin_
{
	meta:
		description = "Hardlock dongle (Alladin)"
	strings:
		$0 = {49 6E 6E 6F 53 65 74 75 70 4C 64 72 57 69 6E 64 6F 77 ?? ?? 53 54 41 54 49}
	condition:
		$0 at entrypoint
}