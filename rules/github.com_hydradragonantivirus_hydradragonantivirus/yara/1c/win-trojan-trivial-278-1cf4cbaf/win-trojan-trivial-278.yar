rule Win_Trojan_Trivial_278
{
strings:
	$a0 = { 2701b120cd21721bb8023dba9e00cd21938bd6b12db440cd217208b43ecd21b44febdcc3 }


condition:
	$a0
}