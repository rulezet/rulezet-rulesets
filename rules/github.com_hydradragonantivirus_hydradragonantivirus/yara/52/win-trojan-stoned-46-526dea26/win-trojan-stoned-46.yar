rule Win_Trojan_Stoned_46
{
strings:
	$a0 = { cbb909002e890e4000b80103cd13bebe03bfbe01b92100f3a5b8010333dbfec1cd13ebc4 }


condition:
	$a0
}