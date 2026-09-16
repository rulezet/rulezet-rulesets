rule Win_Trojan_Suleiman_1
{
strings:
	$a0 = { d142a3b6028916b802b440b9b402ba0000cd21b8004233c933d2cd21b440b91800bab402cd21b8 }


condition:
	$a0
}