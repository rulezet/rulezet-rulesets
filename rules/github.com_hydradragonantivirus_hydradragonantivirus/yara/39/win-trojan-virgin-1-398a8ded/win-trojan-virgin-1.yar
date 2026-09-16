rule Win_Trojan_Virgin_1
{
strings:
	$a0 = { 90eb0490e99f00bae301b41acd21badb0133c9b44ecd2172ebba0102b8023dcd21727a8bd8b90200bae101b43fcd21 }


condition:
	$a0
}