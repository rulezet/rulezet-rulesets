rule Win_Trojan_CV_1
{
strings:
	$a0 = { 2e8d02833e950200740850b80100e8830158be7000b92000bfe80303fd81c77a0283c702f3a4bee70303f5bfe7 }


condition:
	$a0
}