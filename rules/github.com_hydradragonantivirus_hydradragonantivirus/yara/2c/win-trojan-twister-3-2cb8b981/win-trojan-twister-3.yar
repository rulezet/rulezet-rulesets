rule Win_Trojan_Twister_3
{
strings:
	$a0 = { 2902b44ecd217258ba9e00b8023d90cd21722193b000b457cd215152ba0001b90040b440cd215a }


condition:
	$a0
}