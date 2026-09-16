rule Win_Trojan_Trance_1
{
strings:
	$a0 = { 8db71201b93d032e311c83c602e2f887ebb430bf8d06cd213d8d067503e998000e1f1e2bc08ed8bf84008e4502 }


condition:
	$a0
}