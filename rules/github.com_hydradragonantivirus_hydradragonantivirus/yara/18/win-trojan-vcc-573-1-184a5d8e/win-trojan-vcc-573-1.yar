rule Win_Trojan_VCC_573_1
{
strings:
	$a0 = { 02422bc999cd21b440b93d028d960600cd21b43ecd21c3 }


condition:
	$a0
}