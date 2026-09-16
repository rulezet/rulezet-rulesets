rule Win_Trojan_Stoned_10
{
strings:
	$a0 = { 7402b10e890ea001cd5f7218bebe03bfbe01b92100fcf3a5b8010331dbb9010031d2cd5f }


condition:
	$a0
}