rule Win_Trojan_Diablo_1
{
strings:
	$a0 = { fd7728a38600b80057cc5152b97601b44099cc7210b8004233c999ccb90400ba8400b440cc }


condition:
	$a0
}