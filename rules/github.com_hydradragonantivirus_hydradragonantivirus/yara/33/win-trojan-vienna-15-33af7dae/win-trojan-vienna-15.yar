rule Win_Trojan_Vienna_15
{
strings:
	$a0 = { fc8bf281c60a00bf0001b90300f3a48b }


condition:
	$a0
}