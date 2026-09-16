rule Win_Trojan_Anti_4
{
strings:
	$a0 = { e88700bed003e873028b4cfe83e10383c1038344fe0451e8ef00593c007502e2f5e81200817cfe00037603e83600e8 }


condition:
	$a0
}