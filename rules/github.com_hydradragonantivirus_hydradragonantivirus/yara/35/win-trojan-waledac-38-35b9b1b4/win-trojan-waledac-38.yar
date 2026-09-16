rule Win_Trojan_Waledac_38
{
strings:
	$a0 = { 558bec8bd283f0798d558b83f36e81ee603f000003fb53bb88490000685b }


condition:
	$a0
}