rule Win_Trojan_Anti_13
{
strings:
	$a0 = { 8600fbfe0e7b045e2e81bc89fd4d5a75 }


condition:
	$a0
}