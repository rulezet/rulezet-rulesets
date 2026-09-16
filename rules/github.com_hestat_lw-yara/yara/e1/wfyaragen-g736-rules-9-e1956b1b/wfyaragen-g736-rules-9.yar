rule WFYARAGEN_G736_rules_9
{

	meta:
	description = "Part of malware, basic backwards obfuscation"

	strings:

	$re = /strrev\s*\(\s*['"]\s*=ecruos&wordpress\?\/moc\.yadot-syasse\/\/:ptth\s*['"]\s*\)\s*;/ nocase

	condition:
	$re
}