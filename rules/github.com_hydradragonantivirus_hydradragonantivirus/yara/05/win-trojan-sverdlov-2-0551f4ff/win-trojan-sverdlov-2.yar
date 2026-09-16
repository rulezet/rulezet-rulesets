rule Win_Trojan_Sverdlov_2
{
strings:
	$a0 = { ee082e8a840c00b97d07bf2d0003fe }


condition:
	$a0
}