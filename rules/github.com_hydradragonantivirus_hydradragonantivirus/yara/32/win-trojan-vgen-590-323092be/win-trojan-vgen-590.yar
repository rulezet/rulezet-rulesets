rule Win_Trojan_VGEN_590
{
strings:
	$a0 = { 2d03002e89864703b440b944028d960501cd2172bbb440b905008d963d03cd21b8004233d233c9 }


condition:
	$a0
}