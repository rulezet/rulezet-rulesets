rule Win_Trojan_4mat2_1
{
strings:
	$a0 = { b8001cbae8023bc473678bc42d440325f0ff8bf8b9a200be7c01fcf3a5b10489c3d3eb8cd903d95333db53cb }


condition:
	$a0
}