rule Win_Trojan__0407_0001_001_1
{
strings:
	$a0 = { 0300cd21b000e81b00b440b903008d96b800cd215a5983c91fb80157cd21b43ecd21eb8d33c933d2 }


condition:
	$a0
}