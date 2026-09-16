rule Win_Trojan_C_53
{
strings:
	$a0 = { 9413103ed6166f1310aec213d6144c56a210a457dd31f87011a010f8f61191eb103f6517a012a310 }


condition:
	$a0
}