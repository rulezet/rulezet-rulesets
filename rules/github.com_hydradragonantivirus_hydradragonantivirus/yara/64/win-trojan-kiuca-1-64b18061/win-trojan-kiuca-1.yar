rule Win_Trojan_Kiuca_1
{
strings:
	$a0 = { 50cbbe700056bf9500a5a5fa5fc70599008c4502fb1e07b80102b90900ba80000653cd13cb }


condition:
	$a0
}