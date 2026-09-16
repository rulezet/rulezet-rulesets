rule Win_Trojan_CSL_1
{
strings:
	$a0 = { 8bc8b89200bb84008907a186008bd08cc08947028e }


condition:
	$a0
}