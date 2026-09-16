rule Win_Trojan_Dikshev_50
{
strings:
	$a0 = { 39b42d19f0f3a5450af3a5cd0af3a5450af3a5470af3a5cf0af3a5470a8faddec92cfa985a4a2847e2799ec10a7b26470a4a2847ec799ec10e0adffc0ad4d0b639bd4b630206d37908496fb360 }


condition:
	$a0
}