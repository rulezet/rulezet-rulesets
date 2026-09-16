rule Win_Trojan_DiskEraser_1
{
strings:
	$a0 = { c7b601b10132c060cd2672059d6142ebf6cd20 }


condition:
	$a0
}