rule Win_Trojan_Overdoze_2
{
strings:
	$a0 = { 771f2d03002ea3a501b440b9d801cd21b8004233c9cd21b440b90400baa401cd21b801572e }


condition:
	$a0
}