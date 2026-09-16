rule Win_Trojan_Beer_1
{
strings:
	$a0 = { 03b9ac0a2bcb2ea0de012e300743e2fa9d58595bc3e8e2ffb440b9ac0aba03012bca8b1ec40a }


condition:
	$a0
}