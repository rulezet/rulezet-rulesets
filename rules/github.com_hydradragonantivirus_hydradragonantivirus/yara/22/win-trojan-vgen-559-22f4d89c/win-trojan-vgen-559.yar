rule Win_Trojan_VGEN_559
{
strings:
	$a0 = { 1b33c033db33c933d233f633ffcbb8004ccd210e1fa32f1cbb6b1cd1e381c34c048bd381c2 }


condition:
	$a0
}