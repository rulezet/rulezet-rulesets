rule Win_Trojan_Beer_5
{
strings:
	$a0 = { 0c2bcb2ea0de012e300743e2fa9d58595bc3e8e2ffb440b9250cba03012bca8b1e3e0ce86000 }


condition:
	$a0
}