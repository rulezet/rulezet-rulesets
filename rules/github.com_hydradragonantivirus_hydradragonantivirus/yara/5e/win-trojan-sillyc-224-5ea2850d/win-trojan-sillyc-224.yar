rule Win_Trojan_SillyC_224
{
strings:
	$a0 = { 5e81c20301b440b90003cd21b44232c033c933d2cd21 }


condition:
	$a0
}