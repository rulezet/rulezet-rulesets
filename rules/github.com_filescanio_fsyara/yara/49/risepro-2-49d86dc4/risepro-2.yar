rule RisePro_2 : hardened
{
	meta:
		author = "ANY.RUN"
		description = "Detects RisePro (stealer version)"
		date = "2023-11-27"
		reference = "https://any.run/cybersecurity-blog/risepro-malware-communication-analysis/"
		original_yara_name = "RisePro"
		ruleset = "RisePro.yar"
		repository = "anyrun/YARA"
		source_url = "https://github.com/anyrun/YARA/blob/9b9ff743b22b99c96c80d57462fc416576eaa6de/RisePro.yar"
		score = 75

	strings:
		$ = { 74 2e 6d 65 2f 52 69 73 65 50 72 6f 53 55 50 50 4f 52 54 }

	condition:
		any of them
}