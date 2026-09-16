rule Win_Trojan_Killa_1
{
strings:
	$a0 = { 2e010674002e0106760033c035cacacd213d012974121e0633dbe8c802e8b802e81400e85902071f2e8e16 }


condition:
	$a0
}