rule malrtf_pe_embedded : exploit
{
	meta:
		author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detect weaponized RTF documents with embedded executable"

	strings:
				$rtf_payload_01 = "4D5A90" nocase

				$rtf_payload_02 = "50450000"

				$rtf_payload_03 = "2154686973"

				$rtf_payload_04 = "444f53206d6f6465" nocase

	condition:
						uint32be(0) == 0x7B5C7274
		and 3 of ($rtf_payload_*)
}