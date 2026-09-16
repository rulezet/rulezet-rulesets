rule Win_Trojan_Germ_2
{
strings:
	$a0 = { b8f50050a14c00a3477ca14e00a3497ca11304484850b106d3e08ec050fc9c50b84f0050b8 }


condition:
	$a0
}