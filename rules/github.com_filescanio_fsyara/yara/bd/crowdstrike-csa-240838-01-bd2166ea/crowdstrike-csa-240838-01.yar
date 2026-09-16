rule CrowdStrike_CSA_240838_01 : daolpu stealer hardened
{
	meta:
		copyright = "(c) 2024 CrowdStrike Inc."
		description = "C++ stealer delivered via Word documents with macros impersonating CS"
		reports = "CSA-240838"
		version = "202407221342"
		last_modified = "2024-07-22"
		malware_family = "Daolpu"
		score = 75
		reference = "https://www.crowdstrike.com/blog/fake-recovery-manual-used-to-deliver-unidentified-stealer/"

	strings:
		$ = {43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 72 65 73 75 6c 74 2e 74 78 74}
		$ = {44 3a 5c 63 2b 2b 5c 4d 61 6c 5f 43 6f 6f 6b 69 65 5f 78 36 34 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 6d 73 63 6f 72 73 76 63 2e 70 64 62}

	condition:
		all of them
}