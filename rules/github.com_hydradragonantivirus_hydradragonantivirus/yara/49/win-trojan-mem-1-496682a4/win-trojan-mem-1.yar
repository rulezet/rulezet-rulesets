rule Win_Trojan_mem_1
{
strings:
	$a0 = { 40cd218d946a028d1c8bbc73028b0733c789846a0203bc750233c0538b9c1302b90200b440cd21 }


condition:
	$a0
}