rule Win_Trojan_Smog_2
{
strings:
	$a0 = { 654c696e652022633a5c736d6f6764726f702e65786522 }


condition:
	$a0
}