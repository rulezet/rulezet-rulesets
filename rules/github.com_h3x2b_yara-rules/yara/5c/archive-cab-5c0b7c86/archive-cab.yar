rule archive_cab : info archive cab windows
{
	meta:
				description = "Detect CAB archive"

	condition:
                                uint32be(0) == 0x4d534346 and
                uint32be(4) == 0x00000000 
}