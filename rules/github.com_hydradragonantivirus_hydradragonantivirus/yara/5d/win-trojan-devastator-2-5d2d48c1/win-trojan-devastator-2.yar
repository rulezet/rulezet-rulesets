rule Win_Trojan_Devastator_2
{
strings:
	$a0 = { f6e90a009090909090909090cd20e800005d81ed20018db6370189f7b93201ad35003cd0c8ab }


condition:
	$a0
}