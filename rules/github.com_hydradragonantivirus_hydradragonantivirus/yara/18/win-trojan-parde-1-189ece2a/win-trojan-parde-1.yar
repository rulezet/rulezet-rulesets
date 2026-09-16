rule Win_Trojan_Parde_1
{
strings:
	$a0 = { 120589961005b440b978048d960001cd21b8004233c999cd21b440b91c008d960e05cd21b801 }


condition:
	$a0
}