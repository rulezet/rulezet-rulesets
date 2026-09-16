rule Win_Trojan_Castigo_1
{
strings:
	$a0 = { 81ed06019090e87f0183b8530cb10e0f9e9e5e56599eaa9eab8398030de6f90eba49bc0e83b8c30cc32f83985a }


condition:
	$a0
}