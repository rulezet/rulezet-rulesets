rule Win_Trojan_Small_4476
{
strings:
	$a0 = { ff74241c588d80????7704506862343504e854000000508d15a???????525051 }


condition:
	$a0
}