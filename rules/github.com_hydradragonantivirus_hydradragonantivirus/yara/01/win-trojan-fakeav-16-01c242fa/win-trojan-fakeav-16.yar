rule Win_Trojan_Fakeav_16
{
strings:
	$a0 = { 89e8e854000000b801000000c38a00f926e6bb1f0000780000a300006d004f5e }


condition:
	$a0
}