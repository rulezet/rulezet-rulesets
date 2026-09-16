rule Win_Trojan_Mithrand_1
{
strings:
	$a0 = { 06510155061e5657525153502eff2651012e8f065101585b595a5f5e1f075d2eff265101 }


condition:
	$a0
}