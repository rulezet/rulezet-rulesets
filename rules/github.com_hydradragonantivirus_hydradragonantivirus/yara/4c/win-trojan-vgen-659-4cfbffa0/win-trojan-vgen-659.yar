rule Win_Trojan_VGEN_659
{
strings:
	$a0 = { b9dd01be12012e810400004646e2f7e800005d81ed150181fc5350740b8db63802bf000157a4eb111e060e1f0e078db6 }


condition:
	$a0
}