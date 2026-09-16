rule _PEncrypt_v10_
{
	meta:
		description = "PEncrypt v1.0"
	strings:
		$0 = {E8 ?? ?? ?? ?? 5D 81 ED 05 10 40 ?? 8D B5 24 10 40 ?? 8B FE B9 0F ?? ?? ?? BB AD 33 C3 E2}
	condition:
		$0 at entrypoint
}