rule Win_Trojan_Ice_1
{
strings:
	$a0 = { e81800b440b93b02ba0001e80600eb0b90b802428b1e5303cd21c3be3301b9d4018034 }


condition:
	$a0
}