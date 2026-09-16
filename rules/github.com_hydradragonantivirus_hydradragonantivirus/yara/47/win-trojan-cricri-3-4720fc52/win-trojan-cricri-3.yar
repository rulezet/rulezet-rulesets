rule Win_Trojan_CriCri_3
{
strings:
	$a0 = { 33c08ed08ec08ed8be007c8be6fb832e13040a90a11304b106d3e08ec033c0cd13b9 }


condition:
	$a0
}