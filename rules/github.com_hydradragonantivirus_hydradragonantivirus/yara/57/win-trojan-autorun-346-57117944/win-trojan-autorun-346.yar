rule Win_Trojan_Autorun_346
{
strings:
	$a0 = { 5b4175746f72756e5d0d0a6f70656e3d7072657a6f6f2e6578652065 }


condition:
	$a0
}