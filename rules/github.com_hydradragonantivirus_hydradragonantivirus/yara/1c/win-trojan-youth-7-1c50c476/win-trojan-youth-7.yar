rule Win_Trojan_Youth_7
{
strings:
	$a0 = { cf4f8a058a5dff8845ff881de8b6003d004b757c2e }


condition:
	$a0
}