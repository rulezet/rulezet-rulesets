rule Win_Trojan_VGOL_8
{
strings:
	$a0 = { 07f366ab07b000bb930602070f8494ff43cd29e9f4ff0d0a0d0a090954686973207669727573 }


condition:
	$a0
}