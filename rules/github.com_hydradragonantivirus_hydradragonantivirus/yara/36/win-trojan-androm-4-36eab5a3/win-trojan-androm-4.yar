rule Win_Trojan_Androm_4
{
strings:
	$a0 = { b859360000558bec83ec0cc745f803eff20d05de440000c745fc04eff20d0df57500008b45f8812d26d14000a1440000 }


condition:
	$a0
}