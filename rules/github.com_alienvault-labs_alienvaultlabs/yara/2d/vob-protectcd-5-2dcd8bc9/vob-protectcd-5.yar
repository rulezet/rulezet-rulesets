rule _VOB_ProtectCD_5_
{
	meta:
		description = "VOB ProtectCD 5"
	strings:
		$0 = {5F 81 EF BE 40 8B 87 03 C6 57 56 8C A7 FF 10 89 87 5E}
	condition:
		$0 at entrypoint
}