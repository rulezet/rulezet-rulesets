rule Win_Trojan_All_1
{
strings:
	$a0 = { 5a019c0eb80335cd21891e86018c068801fec8fec8cd21891e8a018c068c01ba000156b80325cd21ba0001b801 }


condition:
	$a0
}