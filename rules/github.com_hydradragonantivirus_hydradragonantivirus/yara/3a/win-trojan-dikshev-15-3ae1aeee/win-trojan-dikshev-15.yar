rule Win_Trojan_Dikshev_15
{
strings:
	$a0 = { 2e452a434f4d56918bd6adadb44ecd21ba9e008bfab82e5bae75fda5a4cd215a720793b12bb440cd21 }


condition:
	$a0
}