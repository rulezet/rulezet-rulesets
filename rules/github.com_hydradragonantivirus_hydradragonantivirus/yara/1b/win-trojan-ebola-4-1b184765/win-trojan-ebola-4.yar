rule Win_Trojan_Ebola_4
{
strings:
	$a0 = { 4095f0bfaf01b9090b4840fbfdfb0efc4a4a4d1f909090952730e0821d0090954d4030e08245fb004a2740429047 }


condition:
	$a0
}