rule Win_Trojan_Phalcon_2
{
strings:
	$a0 = { 01033606018a24b91e0483c62b8bfeac32c4aae2fac356e8e4ffb956045a83c2b7b440cd21e8 }


condition:
	$a0
}