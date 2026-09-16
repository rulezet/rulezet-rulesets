rule Win_Trojan_Stoned_57
{
strings:
	$a0 = { 1372ed8a1609000e070ad2741433dbfe060800b80103b90100ba8000cd13eb0b }


condition:
	$a0
}