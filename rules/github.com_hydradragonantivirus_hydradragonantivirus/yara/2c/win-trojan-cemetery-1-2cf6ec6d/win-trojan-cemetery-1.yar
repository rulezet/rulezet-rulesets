rule Win_Trojan_Cemetery_1
{
strings:
	$a0 = { c4064c002e898426fc2e8c8428fc }


condition:
	$a0
}