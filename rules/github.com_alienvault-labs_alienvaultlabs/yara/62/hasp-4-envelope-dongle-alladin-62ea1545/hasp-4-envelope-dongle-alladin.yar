rule _Hasp_4_envelope_dongle_Alladin_
{
	meta:
		description = "Hasp 4 envelope dongle (Alladin)"
	strings:
		$0 = {5C 5C 2E 5C 48 41 52 44 4C 4F 43 4B 2E 56 58 44 ?? ?? ?? ?? 5C 5C 2E 5C 46 45 6E 74 65 44 65}
	condition:
		$0 at entrypoint
}