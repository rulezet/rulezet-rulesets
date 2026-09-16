rule Win_Trojan_QDel_3
{
strings:
	$a0 = { 5921210a0d008db620008bbe0600b82601ffd08bb60600b89202ffd08db623008bbe0600b826 }


condition:
	$a0
}