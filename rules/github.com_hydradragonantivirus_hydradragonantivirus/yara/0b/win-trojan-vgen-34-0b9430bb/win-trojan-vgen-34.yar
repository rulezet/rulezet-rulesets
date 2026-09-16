rule Win_Trojan_Vgen_34
{
strings:
	$a0 = { cdd20000d2008db6cf01bf000157a5a5b44e8d966b02e90600b43ecd21b44fcd217263b8023dba9e00cd218bd88d96cf }


condition:
	$a0
}