rule Win_Trojan_Peed_222
{
strings:
	$a0 = { 7303ffd5c3b9c05f010068ae????008b34245881c65242030089f25266ad69c00000010066adc1c0 }


condition:
	$a0
}