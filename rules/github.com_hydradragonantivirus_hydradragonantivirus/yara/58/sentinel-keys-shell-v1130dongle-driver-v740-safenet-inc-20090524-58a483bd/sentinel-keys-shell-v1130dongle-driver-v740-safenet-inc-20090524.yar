import "pe"
rule _Sentinel_Keys_Shell_V1130Dongle_Driver_V740__SafeNet_Inc__20090524_
{
	meta:
		description = "Sentinel Keys Shell V1.1.3.0(Dongle Driver V7.4.0) -> SafeNet Inc. * 20090524"
	strings:
		$0 = {55 8B EC 81 EC 0C 01 00 00 53 56 57 C7 85 04 FF FF FF 00 00 00 00 C7 45 FC 00 00 00 00 C7 45 EC 00 00 00 00 C7 45 F8 00 00 00 00 C7 85 08 FF FF FF 00 00 00 00 C7 45 E4 04 00 00 00 83 3D ?? ?? ?? ?? 00 74 05 E9 ?? ?? 00 00 A1 ?? ?? ?? ?? 83 C0 01}
	condition:
		$0 at pe.entry_point
}