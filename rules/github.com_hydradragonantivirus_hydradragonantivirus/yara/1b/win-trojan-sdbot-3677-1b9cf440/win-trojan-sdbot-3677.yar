rule Win_Trojan_SdBot_3677
{
strings:
	$a0 = { 4cd600261c69fa7c069a7849e6d9cd9e33f1ccbca714aa99fe211ec8d80730a271a1524a33da44b6d0ab5934ef537e5abd90d85c5cd0bdec4d1b7a8996255ed978d2e564bb3c609dc669316bf22c }


condition:
	$a0
}