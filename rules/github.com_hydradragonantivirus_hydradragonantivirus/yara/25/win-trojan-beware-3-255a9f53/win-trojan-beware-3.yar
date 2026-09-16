rule Win_Trojan_Beware_3
{
strings:
	$a0 = { cd21c38db5840257b931008bfeac3480aae2fa5fc3 }


condition:
	$a0
}