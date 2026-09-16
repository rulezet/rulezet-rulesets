rule _Stealth_PE_v11_
{
	meta:
		description = "Stealth PE v1.1"
	strings:
		$0 = {55 57 56 52 51 53 E8 5D 8B D5 81 ED 63 3A 40 2B 95 C2 3A 40 83 EA 0B 89 95 CB 3A 40 8D B5 CA 3A 40 0F B6}
	condition:
		$0 at entrypoint
}