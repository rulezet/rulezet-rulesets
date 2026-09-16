rule Win_Trojan_VGEN_69
{
strings:
	$a0 = { c08ed8be4c00ad50ad501e07cd1248a31304b106d3e08ec0c7064c0076008c064e00fcb9000233ffbe007cf3a4061f }


condition:
	$a0
}