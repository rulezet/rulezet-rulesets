rule Win_Trojan_Mini_37
{
strings:
	$a0 = { 8986db00b440b9de008bd5cd21b000e83b00b440b903008d96da00cd215a5983c91fb80157 }


condition:
	$a0
}