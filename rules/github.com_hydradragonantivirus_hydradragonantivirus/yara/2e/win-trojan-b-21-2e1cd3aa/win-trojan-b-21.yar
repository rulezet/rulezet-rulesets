rule Win_Trojan_B_21
{
strings:
	$a0 = { cb2ea0dd012e300743e2fa9d58595bc3e8e2ffb440b9c50eba03012bca8b1ede0ee8d201 }


condition:
	$a0
}