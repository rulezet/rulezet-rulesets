rule Win_Trojan_Hupigon_1524
{
strings:
	$a0 = { f97207bd60e72f2f546860eb06e7925b5557b1e80a000000e4dbd0d9b52dd12fe5405e72078a2401dc }


condition:
	$a0
}