rule Win_Trojan_Were_1
{
strings:
	$a0 = { 0500cd21bf8600b090b90f00fcf3aab44233c933d28b1e }


condition:
	$a0
}