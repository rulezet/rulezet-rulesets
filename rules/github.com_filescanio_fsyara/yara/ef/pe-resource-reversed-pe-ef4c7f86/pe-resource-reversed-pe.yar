import "pe"
rule pe_resource_reversed_pe : hardened
{
	meta:
		description = "check for MZ at the end of the of any resource"
		score = 75

	condition:
		pe.is_pe and for any resource in pe.resources : ( uint16be( ( resource.offset + resource.length ) - 2 ) == 0x5a4d )
}