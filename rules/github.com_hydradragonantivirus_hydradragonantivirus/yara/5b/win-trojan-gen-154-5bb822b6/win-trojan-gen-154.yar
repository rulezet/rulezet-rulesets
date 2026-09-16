rule Win_Trojan_Gen_154
{
strings:
	$a0 = { bfc5010e578dbefefe16579a8b0765008946feeb8f8dbefefe1657e8b5fe89ec5dc3145b46726965 }


condition:
	$a0
}