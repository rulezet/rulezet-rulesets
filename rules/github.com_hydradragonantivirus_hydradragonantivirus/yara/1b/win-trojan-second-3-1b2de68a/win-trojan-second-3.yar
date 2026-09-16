rule Win_Trojan_Second_3
{
strings:
	$a0 = { 028b4706538bd8b440b9e602cd21b9ffff5b2b4f0a81e9ea02894f0a8bd383c20a8b470653 }


condition:
	$a0
}