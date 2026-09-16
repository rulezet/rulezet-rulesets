rule Win_Trojan_VGEN_619
{
strings:
	$a0 = { b005b40383e30090cd168bf5f890e863071ef8e81507b430cd213c057303e981000e1f8d960907b409cd2181fb }


condition:
	$a0
}