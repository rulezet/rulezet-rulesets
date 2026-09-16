rule Win_Trojan_Trivial_163
{
strings:
	$a0 = { 01b44ecd21ba9e00b8023dcd21938bd6b440cd21b43ecd21c32a2e632a }


condition:
	$a0
}