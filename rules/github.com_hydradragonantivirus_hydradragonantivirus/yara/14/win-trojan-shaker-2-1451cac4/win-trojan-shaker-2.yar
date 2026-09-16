rule Win_Trojan_Shaker_2
{
strings:
	$a0 = { 53515756b8dcdbcd2132e08b1e0201744f8cd8488ed8b4 }


condition:
	$a0
}