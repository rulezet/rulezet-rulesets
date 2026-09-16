rule Win_Trojan_Mif_5
{
strings:
	$a0 = { 16061e33c08ec026a30400e4408ae0e4403ae075f6e800008bfc8b3d83c40281ef1e0187fde803 }


condition:
	$a0
}