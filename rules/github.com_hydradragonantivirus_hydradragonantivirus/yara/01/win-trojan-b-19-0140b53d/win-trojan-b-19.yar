rule Win_Trojan_B_19
{
strings:
	$a0 = { 013b36fe027502b43fe9a1fe53b82012 }


condition:
	$a0
}