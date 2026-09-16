rule Win_Trojan_TB_4
{
strings:
	$a0 = { 01cd96cd947503e92a00cdec1abe4c01cd96cdb8cdb2be4801cd96cdeccccdec1abe4401cd96 }


condition:
	$a0
}