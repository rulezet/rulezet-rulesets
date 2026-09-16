rule _EXECryptor_vxxxx_
{
	meta:
		description = "EXECryptor vx.x.x.x"
	strings:
		$0 = {68 ?? 10 40 ?? 68 04 01 ?? ?? E8 39 03 ?? ?? 05 ?? 10 40 C6 ?? 5C 68 68 6A ??}
	condition:
		$0 at entrypoint
}