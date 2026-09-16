rule Win_Trojan_Empire_2
{
strings:
	$a0 = { bf2902b90401e8ccffb440b92500ba0001cd21b440b90401ba2902cd21b43ecd21b44febc2b44e }


condition:
	$a0
}