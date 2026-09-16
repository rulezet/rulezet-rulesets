rule Win_Trojan_Tiny_20
{
strings:
	$a0 = { 4d010e59f3a4ba4701b44ecd217301cbb8023d99b29ecd2193b43fba4d015459cd21054d005033 }


condition:
	$a0
}