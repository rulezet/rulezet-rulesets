rule Win_Trojan_Small_5410
{
strings:
	$a0 = { 558bece8????ffffe8????ffff6a??ff15????40005dc3 }

	$a1 = { 43006f006d00700061006e0079004e0061006d00650000000000410064006f006200 }


condition:
	$a0 and $a1
}