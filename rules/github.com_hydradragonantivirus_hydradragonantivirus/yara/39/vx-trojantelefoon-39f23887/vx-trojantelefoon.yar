import "pe"
rule _Vx_TrojanTelefoon_
{
	meta:
		description = "Vx: Trojan.Telefoon"
	strings:
		$0 = {60 1E E8 3B 01 BF CC 01 2E 03 3E CA 01 2E C7 05}
	condition:
		$0 at pe.entry_point
}