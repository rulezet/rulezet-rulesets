rule Win_Trojan_Rain_2
{
strings:
	$a0 = { b440b9e2008d960301cd21b43ecd21b409baa501b439bad001cd21b44feb8eba8000b41acd21 }


condition:
	$a0
}