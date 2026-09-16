rule Win_Trojan_Pandora_2
{
strings:
	$a0 = { e800005d81ed08018c1622022bc08ed08e162202b82135cd21899e24028c8626020e07b80312cd2f2bff4783fff8731a }


condition:
	$a0
}