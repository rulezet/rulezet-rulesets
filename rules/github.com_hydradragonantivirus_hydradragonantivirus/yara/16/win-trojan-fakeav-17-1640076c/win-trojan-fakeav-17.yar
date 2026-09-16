rule Win_Trojan_Fakeav_17
{
strings:
	$a0 = { 558bece8f3dcf8ff8be55dc31b789975a0323941a5 }

	$a1 = { 5f584d571be4573e1c }


condition:
	$a0 and $a1
}