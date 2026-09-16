rule Win_Trojan_Asp_1
{
strings:
	$a0 = { d631db8ec3bb8400268b0f890c890d464647474343268b }


condition:
	$a0
}