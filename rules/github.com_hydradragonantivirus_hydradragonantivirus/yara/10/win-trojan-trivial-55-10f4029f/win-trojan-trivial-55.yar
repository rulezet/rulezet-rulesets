rule Win_Trojan_Trivial_55
{
strings:
	$a0 = { b8013dbad600ba9e00cd2193b4f0b440b173ba000180c55080ed50cd21b40db43ecd21b472 }


condition:
	$a0
}