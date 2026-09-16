rule Win_Trojan_Harrier_2
{
strings:
	$a0 = { 9a45cdabce15926d762ca0d575ab78c69865e49cd7635f6c6447030057ab4b3e1bbe95b77a933ae5 }


condition:
	$a0
}