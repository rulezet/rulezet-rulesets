rule Win_Trojan_VGEN_439
{
strings:
	$a0 = { 4faf75fc83c7028bd7061f0e07b44abbce00cd212ea35c062ea360062ea36406b8004bbb5806 }


condition:
	$a0
}