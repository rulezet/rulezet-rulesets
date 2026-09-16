rule Win_Trojan_Flash_3
{
strings:
	$a0 = { 218cda03d3428ec2b455cd2156bf000183ee080e1fb9d002 }


condition:
	$a0
}