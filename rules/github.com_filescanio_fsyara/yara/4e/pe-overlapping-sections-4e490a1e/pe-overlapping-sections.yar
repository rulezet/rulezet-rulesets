import "pe"
rule pe_overlapping_sections : hardened
{
	meta:
		description = "PE sections have overlapping vrtl or raw addresses"
		score = 50

	condition:
		pe.is_pe and for any i in ( 0 .. pe.number_of_sections - 1 ) : ( for any j in ( i + 1 .. pe.number_of_sections - 1 ) : ( ( pe.sections [ i ] . virtual_address != 0 and pe.sections [ j ] . virtual_address != 0 and pe.sections [ i ] . virtual_address + pe.sections [ i ] . virtual_size > pe.sections [ j ] . virtual_address ) or ( pe.sections [ i ] . raw_data_offset != 0 and pe.sections [ j ] . raw_data_offset != 0 and pe.sections [ i ] . raw_data_offset + pe.sections [ i ] . raw_data_size > pe.sections [ j ] . raw_data_offset ) ) )
}