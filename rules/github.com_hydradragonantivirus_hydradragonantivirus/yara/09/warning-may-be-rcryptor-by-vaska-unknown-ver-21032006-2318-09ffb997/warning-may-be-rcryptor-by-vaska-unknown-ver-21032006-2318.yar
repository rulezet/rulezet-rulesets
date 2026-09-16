import "pe"
rule _Warning_may_be_RCryptor_by_Vaska_unknown_ver__21032006_2318_
{
	meta:
		description = "Warning! may be RCryptor by Vaska unknown ver  (21.03.2006 23:18)"
	strings:
		$0 = {C0 14 13 74 06 80 30}
	condition:
		$0 at pe.entry_point
}