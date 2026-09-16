rule Win_Trojan_Mikrob_3
{
strings:
	$a0 = { cd6080fa0d7403e933ff1e0e1fb409baa303cd211fb90200b80103b600b280cd1341e540e770 }


condition:
	$a0
}