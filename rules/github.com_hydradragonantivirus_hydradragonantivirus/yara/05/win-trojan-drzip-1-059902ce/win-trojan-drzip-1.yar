rule Win_Trojan_Drzip_1
{
strings:
	$a0 = { b440e84c00be0b015981c1f501baed028bfa8a043400880551b90100b440e830005946e2e8 }


condition:
	$a0
}