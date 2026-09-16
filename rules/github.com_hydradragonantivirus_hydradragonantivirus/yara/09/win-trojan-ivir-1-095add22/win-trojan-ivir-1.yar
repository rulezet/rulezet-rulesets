rule Win_Trojan_Ivir_1
{
strings:
	$a0 = { 4478a300018a447aa202011e068ed98ec1b829008d74fdbf0002b17ff3a4071f680001c3601e0680fc4b7542b802 }


condition:
	$a0
}