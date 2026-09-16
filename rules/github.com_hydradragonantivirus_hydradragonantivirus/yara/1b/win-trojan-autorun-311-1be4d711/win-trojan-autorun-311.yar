rule Win_Trojan_Autorun_311
{
strings:
	$a0 = { 5b6175746f72756e5d }

	$a1 = { 7368656c6c5c6f70656e5c636f6d6d616e643d777363726970742e65786520 }

	$a2 = { 2e766273 }


condition:
	$a0 and $a1 and $a2
}