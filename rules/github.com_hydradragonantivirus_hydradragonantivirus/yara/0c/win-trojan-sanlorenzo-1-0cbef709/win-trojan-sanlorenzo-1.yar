rule Win_Trojan_SanLorenzo_1
{
strings:
	$a0 = { 5d81ed08013e8a9ef0040adb7416e8d703bac3038bca8db62d012ec004022e301c46e2f6 }


condition:
	$a0
}