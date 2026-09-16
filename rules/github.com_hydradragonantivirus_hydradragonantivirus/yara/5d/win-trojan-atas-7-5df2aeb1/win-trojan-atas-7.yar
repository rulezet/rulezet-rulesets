rule Win_Trojan_Atas_7
{
strings:
	$a0 = { 01b0c8b9e60cbe130001fe300446e2fb349f7678c4c93677c8c971cec83b6c9770056305e9f57214bc987cf805 }


condition:
	$a0
}