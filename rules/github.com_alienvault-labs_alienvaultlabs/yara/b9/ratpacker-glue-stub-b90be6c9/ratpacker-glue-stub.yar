rule _RatPacker_Glue_stub_
{
	meta:
		description = "RatPacker (Glue) stub"
	strings:
		$0 = {83 3D 55 8B EC 56 57 75 65 68 ?? 01 E8 E6 FF FF 83 C4 04 8B 75 08 A3 85 F6 74 1D 68}
	condition:
		$0 at entrypoint
}