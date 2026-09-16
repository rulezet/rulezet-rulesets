import "pe"
rule _UPX_v0761_dos_exe_
{
	meta:
		description = "UPX v0.76.1 [dos exe"
	strings:
		$0 = {B9 ?? ?? BE ?? ?? 89 F7 1E A9 ?? ?? 8C C8 05 ?? ?? 8E D8 05 ?? ?? 8E C0 FD F3 A5 FC}
	condition:
		$0 at pe.entry_point
}