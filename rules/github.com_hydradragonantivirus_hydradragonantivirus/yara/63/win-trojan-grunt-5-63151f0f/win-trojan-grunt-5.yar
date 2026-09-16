rule Win_Trojan_Grunt_5
{
strings:
	$a0 = { eb1de814003e8b9657028d9e3001b97400311783c3 }


condition:
	$a0
}