rule _CodeCrypt_v016b__v0163b_
{
	meta:
		description = "CodeCrypt v0.16b - v0.163b"
	strings:
		$0 = {E9 2E 03 ?? ?? EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F EB 03 FF 1D}
	condition:
		$0 at entrypoint
}