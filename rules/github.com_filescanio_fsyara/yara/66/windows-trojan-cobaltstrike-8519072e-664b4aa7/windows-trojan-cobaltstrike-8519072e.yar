rule Windows_Trojan_CobaltStrike_8519072e : hardened limited
{
	meta:
		author = "Elastic Security"
		id = "8519072e-3e43-470b-a3cf-18f92b3f31a2"
		fingerprint = "9fc88b798083adbcf25f9f0b35fbb5035a98cdfe55377de96fa0353821de1cc8"
		creation_date = "2021-03-25"
		last_modified = "2021-10-04"
		description = "Identifies Cobalt Strike trial/default versions"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 90
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {55 73 65 72 2d 41 67 65 6e 74 3a}
		$a2 = {77 69 6e 69}
		$a3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 35 4f 21 50 25 40 41 50 5b 34 5c 50 5a 58 35 34 28 50 5e 29 37 43 43 29 37 7d 24 45 49 43 41 52 2d 53 54 41 4e 44 41 52 44 2d 41 4e 54 49 56 49 52 55 53 2d 54 45 53 54 2d 46 49 4c 45 21 24 48 2b 48 2a (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		all of them
}