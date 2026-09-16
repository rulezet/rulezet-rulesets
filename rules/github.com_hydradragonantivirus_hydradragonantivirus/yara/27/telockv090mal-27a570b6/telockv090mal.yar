import "pe"
rule tElockv090mal
{
	meta:
		author="malware-lu"
strings:
		$a0 = { E8 02 00 00 00 E8 00 E8 00 00 00 00 5E 2B }

condition:
		$a0 at pe.entry_point
}