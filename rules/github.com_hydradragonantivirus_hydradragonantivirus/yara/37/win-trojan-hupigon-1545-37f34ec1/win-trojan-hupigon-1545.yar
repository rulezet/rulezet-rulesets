rule Win_Trojan_Hupigon_1545
{
strings:
	$a0 = { 57a03beb6179eef93578c13a036efc6eaaa5c173005a1bd421efadb3e2092c3a217269568bc5fc56b9346ab3900f42ff75e449fdd4eab614ff5c8be2e846fa707c009133dbd0985ea4a28445f5d8 }


condition:
	$a0
}