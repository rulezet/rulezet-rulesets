rule Win_Trojan_Freew_2
{
strings:
	$a0 = { 1252b80104b9010032f6cd135a7304 }


condition:
	$a0
}