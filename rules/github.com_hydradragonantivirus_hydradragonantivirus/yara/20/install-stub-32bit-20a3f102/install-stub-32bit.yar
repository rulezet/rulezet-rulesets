import "pe"
rule _Install_Stub_32bit_
{
	meta:
		description = "Install Stub 32-bit"
	strings:
		$0 = {60 E8 5D 8B D5 81 ED 2B 95 81 EA 06 89 95 83 BD}
	condition:
		$0 at pe.entry_point
}