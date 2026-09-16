rule Win_Trojan_Trivial_364
{
strings:
	$a0 = { 090180340146e2fab54fbb4c00cc20733b3b079701b54e75f532f7be010390f2a5bf08028acfa1040041a304023105 }


condition:
	$a0
}