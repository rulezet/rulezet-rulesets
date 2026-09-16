rule Win_Trojan_Beer_13
{
strings:
	$a0 = { cb2ea0dc012e300743e2fa9d58595bc3e8e2ffb440b99c0dba03012bca8b1eb40de8b101 }


condition:
	$a0
}