rule Win_Trojan_Jak_6
{
strings:
	$a0 = { 0600e80200eb12b931008d9e22008b96ef0031174343e2fac3b41a8d96fe00cd21b8ef00408986ef00bf00018d }


condition:
	$a0
}