rule Win_Trojan_Sily_1
{
strings:
	$a0 = { 0b01beec00300446e2fbb440b9e902ba0000cd2133c98bd1b80042cd21bae902b91c00b440cd21 }


condition:
	$a0
}