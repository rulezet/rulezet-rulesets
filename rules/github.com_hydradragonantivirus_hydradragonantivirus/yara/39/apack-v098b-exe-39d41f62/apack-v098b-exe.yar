import "pe"
rule _aPack_v098b_exe_
{
	meta:
		description = "aPack v0.98b (exe)"
	strings:
		$0 = {93 07 1F 05 ?? ?? 8E D0 BC ?? ?? EA}
	condition:
		$0 at pe.entry_point
}