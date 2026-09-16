rule Win_Trojan_STAL1241_1
{
strings:
	$a0 = { 40bacf02b93e00cd21b8004233c9ba0002cd21b440ba4e02b93a00cd21b8004233c9ba0004cd21 }


condition:
	$a0
}