rule Win_Trojan_Insert_5
{
strings:
	$a0 = { db8bf4fa5886e7504c5886e750eb00ebf35886e75083ec1087f4fbb91b0151cd2ab452cd21268e5ffe33ff803d4d74 }


condition:
	$a0
}