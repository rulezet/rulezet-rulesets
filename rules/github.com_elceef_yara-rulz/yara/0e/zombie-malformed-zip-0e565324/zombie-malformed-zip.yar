rule Zombie_Malformed_ZIP
{
	meta:
		description = "Malformed ZIP with header declaring method STORED while having DEFLATE-compressed payload"
		author = "marcin@ulikowski.pl"
		date = "2026-03-15"
		modified = "2026-03-18"
		hash1 = "7316a4c3cd1cf183925ab4b7e77dbf52b38180ee1faf0156d7ea410f42cb5e76"
		reference = "https://github.com/bombadil-systems/zombie-zip"

	strings:
		$local = {
			50 4b 03 04 			?? 00 			?? 00 			00 00 			?? ?? 			?? ?? 			?? ?? ?? ?? 			?? ?? ?? ?? 			?? ?? ?? ?? 			}

	condition:
		$local at 0 and (uint32(18) != uint32(22)) and (uint8(6) & 0x41) == 0

		
}