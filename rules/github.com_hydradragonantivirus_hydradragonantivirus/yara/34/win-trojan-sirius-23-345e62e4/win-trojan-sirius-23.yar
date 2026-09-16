rule Win_Trojan_Sirius_23
{
strings:
	$a0 = { 582d0801958db62201568b961a02b97c008bfead33c2abe2fac3 }


condition:
	$a0
}