rule EICAR_Encrypted_ZIP
{
	meta:
		description = "Detects EICAR file in any encrypted ZIP archive"
		author = "marcin@ulikowski.pl"
		date = "2022-12-13"

	strings:
		$local = {
			50 4b 03 04 			?? 00 			?? 00 			?? 00 			?? ?? 			?? ?? 			?? ?? ?? ?? 			?? ?? ?? ?? 			?? ?? ?? ?? 			}

	condition:
				for any i in (1..#local) : (
						(uint8(@local[i] + 6) & 0x01 or uint8(@local[i] + 6) & 0x40) and
						uint32(@local[i] + 14) == 0x6851cf3c and
						uint32(@local[i] + 22) == 68
			)
}