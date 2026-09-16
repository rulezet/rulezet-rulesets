rule Win_Trojan_Kode4_11
{
strings:
	$a0 = { be0001bf0201478b04390575f98b44013b45017402ebef83c70381ef????8bf733c0bf01018a05bf????03feb9990203ce4f473bf974088a1532d08815ebf3 }


condition:
	$a0
}