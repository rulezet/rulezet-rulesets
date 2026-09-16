import "pe"
rule _PROPACK_v208_
{
	meta:
		description = "PRO-PACK v2.08"
	strings:
		$0 = {8C D3 8E C3 8C CA 8E DA 8B 0E ?? ?? 8B F1 83 ?? ?? 8B FE D1 ?? FD F3 A5 53}
	condition:
		$0 at pe.entry_point
}