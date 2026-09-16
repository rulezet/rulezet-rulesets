rule Win_Trojan_DR_1
{
strings:
	$a0 = { b8addebaaddecd213d00007502eb6b1eb435b021cd212e891e????2e8c06????b425b0992e8b16????2e8b1e????8edbcd21 }


condition:
	$a0
}