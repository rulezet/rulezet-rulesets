rule Win_Trojan_Wanderer_1
{
strings:
	$a0 = { 028a4414345b88441233d2b93f04b440cd21b000e82b00ba4804b91800b440cd21803e6d0401 }


condition:
	$a0
}