rule Win_Trojan_FridayThe13th_1
{
strings:
	$a0 = { 50cb8cc88ed8e80600e8d900e9040106 }


condition:
	$a0
}