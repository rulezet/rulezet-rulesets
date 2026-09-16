rule Win_Trojan_R_32
{
strings:
	$a0 = { b801faba4559cd16e800005d83ed0ce81400eb26e80f00b440b959028bd5cd21e80300c300002e8db63b00b90f012e }


condition:
	$a0
}