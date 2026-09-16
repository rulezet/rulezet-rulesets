rule Win_Trojan_Jovial_2
{
strings:
	$a0 = { 02b4f488225d4545e2e88beafe86fa02b440b905008d96e702cce8b400b440b9f7018d960501cc }


condition:
	$a0
}