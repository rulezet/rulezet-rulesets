rule _AcidCrypt_
{
	meta:
		description = "AcidCrypt"
	strings:
		$0 = {BE 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0}
		$1 = {9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 87 DD 6A 04 68 10 68 02 6A FF 95 46 23 40}
	condition:
		$0 at entrypoint or $1 at entrypoint
}