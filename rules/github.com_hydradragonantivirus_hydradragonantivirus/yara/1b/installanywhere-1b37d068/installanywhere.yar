import "pe"
rule InstallAnywhere : ZeroG Software Inc
{
	meta:
		author="_pusher_"
		date="2016-07"
	condition:
				(uint32be(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size) == 0x5B3E4E00)
		and
		(uint16be(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size+0x404) == 0x504B)
}