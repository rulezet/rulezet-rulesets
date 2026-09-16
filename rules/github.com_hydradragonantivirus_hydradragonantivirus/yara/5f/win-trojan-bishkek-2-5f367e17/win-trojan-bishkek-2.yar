rule Win_Trojan_Bishkek_2
{
strings:
	$a0 = { 018b1c8d061a0305030003d8b903008d770cbf0001f3a48bf333c08907b41a8d5715cd21b44eb920008d5702cd }


condition:
	$a0
}