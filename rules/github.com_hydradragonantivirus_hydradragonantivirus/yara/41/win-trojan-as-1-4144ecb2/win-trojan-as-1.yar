rule Win_Trojan_AS_1
{
strings:
	$a0 = { 515257561e06e800005e83ee0bb8cdebcd213dbedc744f0658488ec026803e00005a754226a103002d4000723926 }


condition:
	$a0
}