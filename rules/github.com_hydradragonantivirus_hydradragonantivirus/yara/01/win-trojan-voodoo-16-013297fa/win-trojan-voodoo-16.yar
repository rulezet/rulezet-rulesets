rule Win_Trojan_Voodoo_16
{
strings:
	$a0 = { 3c212d2d766f6f646f6f2d2d3e[0-53]6c696e657472616e67652e68746d6c74657874 }


condition:
	$a0
}