rule _CodeCrypt_v015b_
{
	meta:
		description = "CodeCrypt v0.15b"
	strings:
		$0 = {E9 2E 03 ?? ?? EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7}
	condition:
		$0 at entrypoint
}