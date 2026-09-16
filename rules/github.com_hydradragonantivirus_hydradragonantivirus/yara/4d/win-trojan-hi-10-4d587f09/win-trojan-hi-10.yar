rule Win_Trojan_Hi_10
{
strings:
	$a0 = { b80042cd21ba8d03b91800b440cd2172b133c933d2b80242cd21b44033d2b97f03cd21b80157 }


condition:
	$a0
}