rule Win_Trojan_Crist_1
{
strings:
	$a0 = { 2214a0841a8887521aff062416ff062214c41e241626803f0075d9b8028250b8521a50e8310a }


condition:
	$a0
}