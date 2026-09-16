rule Win_Trojan_Bancos_667
{
strings:
	$a0 = { 4dfdc265e4cc2ded3e1fe7af3e076b4aeef0053d8284dcce67f2f29f9da881bff8f1920c22e6f9d5da0da5fb9bf8cb0746f49c3a30e05b5b162f88d6a01c64eed0b019ca6b0d45fa7747fd297ab887ed }


condition:
	$a0
}