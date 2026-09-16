rule Win_Trojan_Nucleii_4
{
strings:
	$a0 = { b440ba0001cd21595ab80157cd21b43ecd21b80143 }


condition:
	$a0
}