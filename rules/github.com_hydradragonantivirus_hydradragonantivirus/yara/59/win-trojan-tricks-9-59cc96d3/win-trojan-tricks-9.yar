rule Win_Trojan_Tricks_9
{
strings:
	$a0 = { 5e81ee0301e8c300aae1c154aae1c354e11bd8c1db54669c98742735ed5768efcb559874de }


condition:
	$a0
}