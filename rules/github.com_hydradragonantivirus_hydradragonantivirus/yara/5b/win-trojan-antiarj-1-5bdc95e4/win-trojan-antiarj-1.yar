rule Win_Trojan_AntiARJ_1
{
strings:
	$a0 = { 8a971701f6d2b402cd214383fb1872f0b8004ccd21f5f2f6f6f6ba858bdf955d93df929a988c }


condition:
	$a0
}