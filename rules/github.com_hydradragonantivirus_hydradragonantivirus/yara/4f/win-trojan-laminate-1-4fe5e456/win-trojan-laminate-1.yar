rule Win_Trojan_Laminate_1
{
strings:
	$a0 = { e87200b9eb09bbeb09b805feebfc80c43bebf4bb20010e07cd21b001cd21eb02ebfec606280182b080e621b80300b93f42fa99cd26fbea0000ffffb8004ccd215b4c616d696e617465205472 }


condition:
	$a0
}