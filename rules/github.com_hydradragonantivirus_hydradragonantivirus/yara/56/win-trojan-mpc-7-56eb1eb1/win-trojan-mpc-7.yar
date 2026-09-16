rule Win_Trojan_MPC_7
{
strings:
	$a0 = { 9ab42acd2180fe0a721280fa17720d81f9c9077207b42ccd2180fa50b41aba8000cd21c3cd }


condition:
	$a0
}