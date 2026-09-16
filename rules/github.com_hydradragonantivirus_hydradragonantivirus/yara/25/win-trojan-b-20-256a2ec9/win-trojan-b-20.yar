rule Win_Trojan_B_20
{
strings:
	$a0 = { cb2ea0d2012e300743e2fa9d58595bc3e8e2ffb440b9230eba03012bca8b1e3c0ee82401 }


condition:
	$a0
}