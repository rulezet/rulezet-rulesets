rule _APatch_GUI_v11_
{
	meta:
		description = "APatch GUI v1.1"
	strings:
		$0 = {60 E8 5D 81 ED 92 1A 44 B8 8C 1A 44 03 C5 2B 85 CD 1D 44 89 85 D9 1D 44 80 BD C4 1D}
	condition:
		$0 at entrypoint
}