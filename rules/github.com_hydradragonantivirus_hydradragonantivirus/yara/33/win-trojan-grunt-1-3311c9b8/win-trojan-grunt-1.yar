rule Win_Trojan_Grunt_1
{
strings:
	$a0 = { 3e8b9657028d9e3001b97400311783c302e2f9c3b90000e2fec3e800005d81ed2801e8d8ff }


condition:
	$a0
}