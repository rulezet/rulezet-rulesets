rule Win_Trojan_Dikshev_21
{
strings:
	$a0 = { 4d41ba2901b44ecd21721bbf9e008bd7b02eae75fda5a4b45bcd21720993b22e87cab440cd21c32a2e65 }


condition:
	$a0
}