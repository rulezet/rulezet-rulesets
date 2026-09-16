rule Win_Trojan_JumpBoot_1
{
strings:
	$a0 = { 0500108ed80500108ec033dbfcba8000b90100b011b402cd13b111c606000000c60601000cc60602000633c08bf0 }


condition:
	$a0
}