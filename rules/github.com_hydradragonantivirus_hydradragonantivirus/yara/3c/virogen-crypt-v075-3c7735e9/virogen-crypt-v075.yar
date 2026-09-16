import "pe"
rule _Virogen_Crypt_v075_
{
	meta:
		description = "Virogen Crypt v0.75"
	strings:
		$0 = {33 C0 8B B8 ?? 8B 90 04 85 FF 74 1B 33 C9 50 EB 0C 8A 04 39 C0 C8 04 34 1B 88 04 39 41 3B CA 72 F0}
	condition:
		$0 at pe.entry_point
}