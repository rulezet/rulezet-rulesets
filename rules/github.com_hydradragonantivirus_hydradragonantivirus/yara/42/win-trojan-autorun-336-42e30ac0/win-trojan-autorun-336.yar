rule Win_Trojan_Autorun_336
{
strings:
	$a0 = { 5b6175746f72756e5d0d0a6f70656e3d63727376632e6578650d0a7368656c6c5c313d5a41594c45 }


condition:
	$a0
}