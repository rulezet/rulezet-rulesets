rule Win_Trojan_Mahon_1
{
strings:
	$a0 = { 02c686810501b440b950058d960501cd21e8d901b440b91c008d968605cd21e8bd01b43ecd21 }


condition:
	$a0
}