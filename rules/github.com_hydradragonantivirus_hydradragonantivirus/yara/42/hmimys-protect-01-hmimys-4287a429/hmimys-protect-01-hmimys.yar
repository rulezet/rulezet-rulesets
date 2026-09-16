import "pe"
rule _hmimys_protect_01__hmimys_
{
	meta:
		description = "hmimys protect 0.1 -> hmimys"
	strings:
		$0 = {5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8}
	condition:
		$0 at pe.entry_point
}