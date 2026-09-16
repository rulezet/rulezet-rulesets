rule Win_Trojan_Autorun_486
{
strings:
	$a0 = { 6f70656e3d74656d706c6174652e7064662069636f6e3d6175746f72756e2e69636f }


condition:
	$a0
}