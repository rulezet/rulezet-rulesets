rule Win_Trojan_Szamalk_3
{
strings:
	$a0 = { 7303e9830080fa017402eb7c90b00250b980008b1642011ebb00008edbcd269d1f81064201 }


condition:
	$a0
}