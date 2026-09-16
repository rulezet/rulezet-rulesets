rule Win_Trojan_Interceptor_2
{
strings:
	$a0 = { b903008bd683c20dcd218b54068b4c04 }


condition:
	$a0
}