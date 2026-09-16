rule Win_Trojan_Bancos_1052
{
strings:
	$a0 = { fa2d6919caa147080e516d2787e08075652b985a5ecafe7091a5f5a07d01bacfe1ee19329c43f6a8c6f528180d329b81b973eb13e841a930208ccf6e3f9847b3 }


condition:
	$a0
}