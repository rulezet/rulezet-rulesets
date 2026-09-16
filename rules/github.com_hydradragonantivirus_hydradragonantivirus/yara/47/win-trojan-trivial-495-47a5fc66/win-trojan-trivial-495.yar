rule Win_Trojan_Trivial_495
{
strings:
	$a0 = { eb01b44ecd217220ba9e00b8013dcd218bd8b440b9f100ba0001cd21720ab43ecd21b44fcd2173 }


condition:
	$a0
}