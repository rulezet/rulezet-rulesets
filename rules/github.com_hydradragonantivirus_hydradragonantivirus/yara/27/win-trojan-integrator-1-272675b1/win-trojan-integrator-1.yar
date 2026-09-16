rule Win_Trojan_Integrator_1
{
strings:
	$a0 = { 0609d96278b4b56f7f803977770220d9dd91d19ebf3100a044484a50f5f9fb01a7abadb35a5e00b1b5 }


condition:
	$a0
}