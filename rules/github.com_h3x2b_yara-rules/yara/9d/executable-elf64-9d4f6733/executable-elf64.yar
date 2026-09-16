rule executable_elf64 : info executable linux
{
	meta:
				description = "Detect ELF 64 bit executable based on ELF magic"

	condition:
                                uint32be(0) == 0x7f454c46 and
		uint8(4) == 0x02
}