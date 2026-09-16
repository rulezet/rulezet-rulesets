rule _CodeCrypt_v0164_
{
	meta:
		description = "CodeCrypt v0.164"
	strings:
		$0 = {43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43}
	condition:
		$0 at entrypoint
}