rule Win_Trojan_Sirius_39
{
strings:
	$a0 = { 2075d3aa99542073e67f9f72d2b5552645bb4753e65adfc5fc509f72ea5152ea5853a8ca9f75 }


condition:
	$a0
}