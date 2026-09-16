rule Win_Trojan_Autorun_160
{
strings:
	$a0 = { 687372697273675a3c000000ffffffff0d0000003a5c6175746f72756e2e696e66000000558b }


condition:
	$a0
}