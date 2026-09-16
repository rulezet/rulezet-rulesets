rule Win_Trojan_B_95
{
strings:
	$a0 = { 0102cd13b404cd1a81fa1908752ab800b88ec033ffb9d002b8b07ffcf3abb9800251b419f3ab59 }


condition:
	$a0
}