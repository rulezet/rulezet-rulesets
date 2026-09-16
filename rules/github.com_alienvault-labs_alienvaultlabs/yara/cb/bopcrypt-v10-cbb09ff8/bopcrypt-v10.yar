rule _BopCrypt_v10_
{
	meta:
		description = "BopCrypt v1.0"
	strings:
		$0 = {55 8B EC 81 EC 0C 02 56 BE 04 01 8D 85 F8 FE FF FF 56 50 6A FF 15 54 10 40 8A 8D F8 FE FF FF 33 D2 84 C9 8D 85 F8 FE FF FF 74}
	condition:
		$0 at entrypoint
}