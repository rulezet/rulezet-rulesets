rule Win_Trojan_April_2
{
strings:
	$a0 = { 0e1fbe0301ba9627b9c102ac32c232c632c18844ffe2f4 }


condition:
	$a0
}