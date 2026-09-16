rule Win_Trojan_AK_1
{
strings:
	$a0 = { 33c933d2cd21b440b905008bd581c2f100cd21721bb8024233c933d2cd21b440b9fa008bd5cd21 }


condition:
	$a0
}