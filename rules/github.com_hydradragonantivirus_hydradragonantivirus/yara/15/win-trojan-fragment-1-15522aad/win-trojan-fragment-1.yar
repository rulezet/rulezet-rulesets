rule Win_Trojan_Fragment_1
{
strings:
	$a0 = { 8100e8ee00730cb409ba0301cd21b8004ccd21bad80181fc00407709b409cd21b8014ccd21e8a6007305ba4701eb }


condition:
	$a0
}