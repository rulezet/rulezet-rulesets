rule Win_Trojan_Autorun_501
{
strings:
	$a0 = { 5b4175746f52756e5d0d0a3b4f5341346c70335a6b534c6a4c6163730d0a6f70656e3d706f6f }


condition:
	$a0
}