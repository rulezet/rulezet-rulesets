rule Win_Trojan_Vpp_2
{
strings:
	$a0 = { 21c3b43ecd21c3b80157cd21c3b80143cd21c3b43fcd21c3b41be8ddfe80c44086e0aae2f3 }


condition:
	$a0
}