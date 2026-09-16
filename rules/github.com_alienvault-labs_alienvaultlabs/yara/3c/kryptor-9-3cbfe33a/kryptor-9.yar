rule _kryptor_9_
{
	meta:
		description = "kryptor 9"
	strings:
		$0 = {8B 0C 24 E9 0A 7C 01 AD 42 40 BD BE 9D 7A}
	condition:
		$0 at entrypoint
}