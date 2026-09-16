rule Win_Trojan_Vienna_56
{
strings:
	$a0 = { 80f2aeb90400acae75ede2fa5e0789bc160089f781 }


condition:
	$a0
}