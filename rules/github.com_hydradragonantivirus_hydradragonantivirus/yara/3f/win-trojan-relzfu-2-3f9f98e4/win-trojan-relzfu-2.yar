rule Win_Trojan_Relzfu_2
{
strings:
	$a0 = { d5b90600cd21b801575a59cd21b43ecd21b80001ffe0 }


condition:
	$a0
}