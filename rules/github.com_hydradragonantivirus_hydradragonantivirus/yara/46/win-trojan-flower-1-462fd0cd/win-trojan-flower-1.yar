rule Win_Trojan_Flower_1
{
strings:
	$a0 = { 8a160200bb36008a0732c28807fec24381fb72037ef1 }


condition:
	$a0
}