rule ole_object : info ole windows
{
	meta:
				description = "Detect OLE (Object Linking and Embedding)"

	condition:
                                uint32be(0) == 0xd0cf11e0 and
                uint32be(4) == 0xa1b11ae1
}