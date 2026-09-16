import "pe"
rule _Unknown_Packer__Northfox_
{
	meta:
		description = "Unknown Packer -> Northfox"
	strings:
		$0 = {54 59 68 61 7A 79}
	condition:
		$0 at pe.entry_point
}