rule Win_Trojan_Rocksteady_1
{
strings:
	$a0 = { 9a02f32ea41e8ed9be20008d7d19b8f501874464ab8cc0 }


condition:
	$a0
}