rule Win_Trojan_VCS1_2
{
strings:
	$a0 = { 33c08ed0bc007ccd12b106d3e0b900012bc1a34100ba8000b902008ec0bb0000b80602cd13 }


condition:
	$a0
}