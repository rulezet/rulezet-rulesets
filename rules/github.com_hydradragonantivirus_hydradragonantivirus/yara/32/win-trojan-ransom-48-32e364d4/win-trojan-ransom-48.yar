rule Win_Trojan_Ransom_48
{
strings:
	$a0 = { 558bec83ec18c745ecbeffdfbdc745f4bdffdfbdc745f012000000ff45f06808834000ff15ec8540006a33ff15e08540006a33ff15e48540008d }


condition:
	$a0
}