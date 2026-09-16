rule Win_Trojan_VCL_24
{
strings:
	$a0 = { e80000905d81ed0601e81f024c771fc39179c1c04a39999664654a3c4a2d4b25402d41c175ee0ce04b25929a9275db4c }


condition:
	$a0
}