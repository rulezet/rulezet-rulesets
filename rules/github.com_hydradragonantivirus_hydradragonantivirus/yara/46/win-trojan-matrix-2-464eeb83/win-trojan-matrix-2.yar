rule Win_Trojan_Matrix_2
{
strings:
	$a0 = { 07750580fa077417beea0103f5bf0001a5a5b8000150c3eb05b8004ccd21c3be580103f58bfe }


condition:
	$a0
}