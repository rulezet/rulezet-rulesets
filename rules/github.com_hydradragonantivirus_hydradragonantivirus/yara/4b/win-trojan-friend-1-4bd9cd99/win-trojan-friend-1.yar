rule Win_Trojan_Friend_1
{
strings:
	$a0 = { b90300baa002cd2193b440b92d01ba0001cd21b43ecd }


condition:
	$a0
}