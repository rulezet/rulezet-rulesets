rule Win_Trojan_Satria_1
{
strings:
	$a0 = { b801028b0e270083f908ba80007503cd13cbba0001cd13cb601e060e1f0e07bb0002b80102 }


condition:
	$a0
}