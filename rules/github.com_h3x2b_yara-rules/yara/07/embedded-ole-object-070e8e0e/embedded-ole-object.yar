rule embedded_ole_object : info embedded ole windows
{
	meta:
				description = "Detect embedded OLE (Object Linking and Embedding)"

	strings:
		$msdocfile_hexstring = { D0 CF 11 E0 A1 B1 1A E1 }

	condition:
                		$msdocfile_hexstring
}