rule Win_Trojan_Agent_32822
{
strings:
	$a0 = { 7b6bb21a4d246816c43186cd9bcf140e6a0c53fbc527bd34fff7de28b6cd09474df0273a2116a50cce0422d404323ffc89a5a274b1d5931ea038c2c5974ca1817b }


condition:
	$a0
}