rule Win_Trojan_B_6
{
strings:
	$a0 = { 8ed8be4c00ad50ad50cd1248a31304b106d3e08ec04e4ec744fe7f008c04fcb9000233ffbe00 }


condition:
	$a0
}