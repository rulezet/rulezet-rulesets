rule Win_Trojan_Stoned_64
{
strings:
	$a0 = { 6c040e1f891e6501be1500e8c9ffb8010331db31d2b101803e0800007403ba80009c2eff1e09 }


condition:
	$a0
}