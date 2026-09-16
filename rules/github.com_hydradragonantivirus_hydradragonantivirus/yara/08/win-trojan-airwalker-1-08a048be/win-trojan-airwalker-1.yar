rule Win_Trojan_Airwalker_1
{
strings:
	$a0 = { 760989f7b98100adcc7304abe2f9c335633b73f7e8e8ff61cd21e8e2ffe950ff }


condition:
	$a0
}