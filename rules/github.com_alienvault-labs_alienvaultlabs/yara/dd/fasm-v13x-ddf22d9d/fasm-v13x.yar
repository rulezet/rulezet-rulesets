rule _FASM_v13x_
{
	meta:
		description = "FASM v1.3x"
	strings:
		$0 = {E8 ?? 6E ?? ?? 55 89 E5 8B 7D 0C 8B 75 08 89 F8 8B 5D 10}
	condition:
		$0 at entrypoint
}