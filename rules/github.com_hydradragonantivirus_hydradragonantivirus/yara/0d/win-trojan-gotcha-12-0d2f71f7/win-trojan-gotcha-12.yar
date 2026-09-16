rule Win_Trojan_Gotcha_12
{
strings:
	$a0 = { f0bf0001b91800f3a40eb8000150b8dadacd2180fca574 }


condition:
	$a0
}