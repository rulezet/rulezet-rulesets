rule Win_Trojan_Small_156
{
strings:
	$a0 = { 7554fec074e1fec8754c601eb8023dcde772418bd8 }


condition:
	$a0
}