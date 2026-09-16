rule Win_Trojan_Lovestar_1
{
strings:
	$a0 = { 633a5c64627061792e626174[0-15]7368656c6c2822633a5c64726f706d652e766273 }


condition:
	$a0
}