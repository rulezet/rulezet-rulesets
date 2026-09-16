rule Win_Trojan_Zbot_1242
{
strings:
	$a0 = { 89ff8b442404505d55ff15344a4100508b1c2483c40483fb0075195089e05068 }


condition:
	$a0
}