rule Win_Trojan_Agent_31373
{
strings:
	$a0 = { 757332680cb22e5b5970b77660312066026e6649ff1adc96a2211b6f706a7fa8b4b4b0ffff6d817af5b7006eb0b3a7b5a1b2a4 }


condition:
	$a0
}