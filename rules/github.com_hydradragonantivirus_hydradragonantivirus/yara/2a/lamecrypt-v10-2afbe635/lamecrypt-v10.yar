import "pe"
rule _LameCrypt_v10_
{
	meta:
		description = "LameCrypt v1.0"
	strings:
		$0 = {54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED F6 73 40 ?? 2B 85 87 75 40 ?? 83 E8}
	condition:
		$0 at pe.entry_point
}