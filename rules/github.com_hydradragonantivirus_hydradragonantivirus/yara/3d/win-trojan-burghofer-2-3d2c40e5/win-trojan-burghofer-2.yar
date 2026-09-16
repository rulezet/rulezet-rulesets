rule Win_Trojan_Burghofer_2
{
strings:
	$a0 = { cd215b488ec0fa26c70601000000 }


condition:
	$a0
}