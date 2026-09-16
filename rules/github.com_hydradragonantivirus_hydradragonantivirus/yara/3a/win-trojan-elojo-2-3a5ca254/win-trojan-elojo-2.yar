rule Win_Trojan_Elojo_2
{
strings:
	$a0 = { db3dd00776d65026c7451500002d0300a39100b440b90400ba9000cd213d000074ba5826 }


condition:
	$a0
}