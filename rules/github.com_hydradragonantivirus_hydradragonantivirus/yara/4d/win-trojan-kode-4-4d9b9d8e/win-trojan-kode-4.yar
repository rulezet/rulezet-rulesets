rule Win_Trojan_Kode_4
{
strings:
	$a0 = { 568b7401bfae0103fe8b058a4d02bf00018905884d02b44ebaa50103d6cd217303eb6c90b8023dba9e00cd21 }


condition:
	$a0
}