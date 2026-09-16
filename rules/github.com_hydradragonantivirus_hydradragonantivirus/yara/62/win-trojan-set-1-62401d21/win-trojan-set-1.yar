rule Win_Trojan_Set_1
{
strings:
	$a0 = { 8e222169c705533a3b393633f9c43b40cb9cff80000080d17f44416bdb9755506ae0bdda8a }


condition:
	$a0
}