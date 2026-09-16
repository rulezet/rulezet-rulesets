rule Win_Trojan_Kobr_2
{
strings:
	$a0 = { 57bf60011e579a670bff009af404ff005dcb0c726564616b746e612e7478740c6b6f6272 }


condition:
	$a0
}