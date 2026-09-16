rule Win_Trojan_Remember_2
{
strings:
	$a0 = { 03003e89869505b440b90705908d960501cd21b8004233c999cd21b440b905008d969405cd21b8 }


condition:
	$a0
}