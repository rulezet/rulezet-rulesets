rule Win_Trojan_Jvirus_1
{
strings:
	$a0 = { d71feb0021f2bb76244f31c781f3252509f640b952d2f7d281f1dada09c68037954ffc433f46e2f64a481ff7d7 }


condition:
	$a0
}