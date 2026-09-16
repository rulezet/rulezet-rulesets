rule Win_Trojan_Fakesec_13
{
strings:
	$a0 = { 6800a04600ba??30400066832200ff32588bc8f9143b03088b411cc1c8082c003c6059720990909090e9??fbfffffa00 }


condition:
	$a0
}