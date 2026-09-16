rule voidlink_implant : malware hardened limited
{
	meta:
		name = "voidlink_implant"
		category = "persistence"
		description = "Detects strings which are a part of the VoidLink implant."
		author = "SquiblydooBlog"
		created = "2026-01-16"
		reliability = 50
		tlp = "TLP:CLEAR"
		reference = "https://research.checkpoint.com/2026/voidlink-the-cloud-native-malware-framework/"
		sample1 = "15cb93d38b0a4bd931434a501d8308739326ce482da5158eb657b0af0fa7ba49"
		sample2 = "05eac3663d47a29da0d32f67e10d161f831138e10958dcd88b9dc97038948f69"
		sample3 = "28c4a4df27f7ce8ced69476cc7923cf56625928a7b4530bc7b484eec67fe3943"
		sample4 = "4c4201cc1278da615bacf48deef461bf26c343f8cbb2d8596788b41829a39f3f"
		sample5 = "6850788b9c76042e0e29a318f65fceb574083ed3ec39a34bc64a1292f4586b41"
		sample6 = "6dcfe9f66d3aef1efd7007c588a59f69e5cd61b7a8eca1fb89a84b8ccef13a2b"
		score = 80

	strings:
		$credential_theft_1 = {74 6f 74 61 6c 5f 68 61 72 76 65 73 74 73 22}
		$credential_theft_2 = {2e 67 69 74 2d 63 72 65 64 65 6e 74 69 61 6c 73}
		$credential_theft_3 = {22 73 73 68 5f 63 6f 6e 66 69 67 5f 66 6f 75 6e 64}
		$debugging_1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 66 61 69 6c 65 64 20 74 6f 20 6b 69 6c 6c 20 70 72 6f 63 65 73 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$debugging_2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 50 72 6f 63 65 73 73 41 6c 72 65 61 64 79 45 78 65 63 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$debugging_3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 46 61 69 6c 65 64 20 74 6f 20 63 6f 6e 6e 65 63 74 20 74 6f 20 43 32 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$debugging_4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 65 72 72 6f 72 3a 20 5b 43 68 61 69 6e 45 78 65 63 75 74 6f 72 5d 20 46 61 69 6c 65 64 20 74 6f 20 73 70 61 77 6e 20 73 68 65 6c 6c 3a 20 65 72 72 6f 72 3a 20 5b 43 68 61 69 6e 45 78 65 63 75 74 6f 72 5d 20 46 61 69 6c 65 64 20 74 6f 20 77 61 69 74 20 66 6f 72 20 73 68 65 6c 6c 3a 20 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$stealth_1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 73 74 65 61 6c 74 68 5f 6d 61 6e 61 67 65 72 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$stealth_2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 73 74 65 61 6c 74 68 20 66 65 61 74 75 72 65 73 20 66 61 69 6c 65 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$stealth_3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 53 74 65 61 6c 74 68 20 61 63 74 69 76 61 74 69 6f 6e 20 66 61 69 6c 65 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		uint16( 0 ) == 0x457f and filesize < 6000KB and all of ( $credential_theft* ) and 3 of ( $debugging* ) and 1 of ( $stealth* )
}