rule Win_Trojan_Discom_2
{
strings:
	$a0 = { cd21721f8bf18bfab80242b9ffffba }


condition:
	$a0
}