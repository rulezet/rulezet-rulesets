rule _kryptor_6_
{
	meta:
		description = "kryptor 6"
	strings:
		$0 = {EB 6A 87}
	condition:
		$0 at entrypoint
}