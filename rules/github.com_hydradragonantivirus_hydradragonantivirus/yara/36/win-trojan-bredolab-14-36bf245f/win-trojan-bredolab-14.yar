rule Win_Trojan_Bredolab_14
{
strings:
	$a0 = { ff1508204000ff1508204000ff1508204000ff1508204000 }


condition:
	$a0
}