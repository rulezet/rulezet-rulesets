rule Win_Trojan_Pizelun_2
{
strings:
	$a0 = { 1fbff40dbb370101f701f343310fd1c139fb75f7c3 }


condition:
	$a0
}