import "pe"
rule pe_resource_base64d_pe : hardened
{
	meta:
		description = "looking for probable base64 encoded PE headers in the resources"
		score = 75

	condition:
		pe.is_pe and for any resource in pe.resources : ( uint32be( resource.offset ) == 0x54567151 and uint32be( resource.offset + 4 ) == 0x41414D41 )
}