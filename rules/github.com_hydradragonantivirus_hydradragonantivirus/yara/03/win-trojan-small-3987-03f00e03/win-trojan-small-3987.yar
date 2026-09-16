rule Win_Trojan_Small_3987
{
strings:
	$a0 = { be674523018d3dff????0281efff65290289fe8d9fc008fe7f81eb4404fe7f6a0089e25252526a006a00ff15 }


condition:
	$a0
}