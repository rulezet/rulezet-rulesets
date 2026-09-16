rule _MinGW_v32x_main_
{
	meta:
		description = "MinGW v3.2.x (main)"
	strings:
		$0 = {55 89 E5 83 EC 08 C7 04 24 01 ?? ?? ?? FF 15 FC 40 40 ?? E8 68 ?? ?? ?? 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 ?? ?? ?? FF 15 FC 40 40 ?? E8 48 ?? ?? ?? 89 EC 31 C0 5D C3 89}
	condition:
		$0 at entrypoint
}