rule _VOB_ProtectCD_
{
	meta:
		description = "VOB ProtectCD"
	strings:
		$0 = {9C 55 E8 EC ?? ?? ?? 87 D5 5D 60 87 D5 80 BD 15 27 40 ??}
	condition:
		$0 at entrypoint
}