rule Powershell_Downloader_POWERGAP : hardened
{
	meta:
		description = "Detects POWERGAP downloader used against Ukrainian ICS"
		author = "mmuir@cadosecurity.com"
		date = "2022-04-12"
		license = "Apache License 2.0"
		score = 60

	strings:
		$a = {53 74 61 72 74 2d 77 6f 72 6b}
		$b = {24 47 70 6f 47 75 69 64}
		$c = {24 53 6f 75 72 63 65 46 69 6c 65}
		$d = {24 44 65 73 74 69 6e 61 74 69 6f 6e 46 69 6c 65}
		$e = {24 61 70 70 4e 61 6d 65}
		$f = {4c 44 41 50 3a 2f 2f 52 4f 4f 54 44 53 45}
		$g = {47 50 54 2e 49 4e 49}
		$h = {47 65 74 2d 57 6d 69 4f 62 6a 65 63 74}

	condition:
		5 of them
}