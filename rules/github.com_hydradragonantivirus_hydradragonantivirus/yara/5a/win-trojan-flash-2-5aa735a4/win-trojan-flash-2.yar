rule Win_Trojan_Flash_2
{
strings:
	$a0 = { eb05eac0e4b3f1fbc60705b82135cd }


condition:
	$a0
}