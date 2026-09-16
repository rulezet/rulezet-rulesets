rule Win_Trojan_GOV_1
{
strings:
	$a0 = { 0a255056e89f1683c408c45efc26ff771c26ff771a56e8680b83c4068b46fc051600ff76fe50 }


condition:
	$a0
}