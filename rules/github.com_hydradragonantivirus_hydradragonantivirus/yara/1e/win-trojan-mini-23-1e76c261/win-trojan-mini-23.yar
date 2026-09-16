rule Win_Trojan_Mini_23
{
strings:
	$a0 = { 8cc80500108ec0b98200be000133fff3a406b8170050cbba0001b41acd211eba7c01b90300b44ecd2172361f1eba1e01 }


condition:
	$a0
}