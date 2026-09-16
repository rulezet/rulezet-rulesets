rule Win_Trojan_FrogsAlley_1
{
strings:
	$a0 = { 0433c08ec0268a261704e460f6c4 }


condition:
	$a0
}