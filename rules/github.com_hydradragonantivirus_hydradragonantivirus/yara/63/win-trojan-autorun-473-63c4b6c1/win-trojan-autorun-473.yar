rule Win_Trojan_Autorun_473
{
strings:
	$a0 = { 5b6175746f72756e5d207368656c6c657865637574653d6e6f6467706d686f2e657865 }


condition:
	$a0
}