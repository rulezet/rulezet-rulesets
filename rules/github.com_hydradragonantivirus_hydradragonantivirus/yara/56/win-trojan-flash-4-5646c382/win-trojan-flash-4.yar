rule Win_Trojan_Flash_4
{
strings:
	$a0 = { d00390cd27071f2e80bca10201740b8cc82d }


condition:
	$a0
}