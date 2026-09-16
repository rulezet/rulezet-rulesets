rule Win_Trojan_Mich_1
{
strings:
	$a0 = { 9c0390ba0001b440e8ab01598b16db018eda33d2b440e89d010e1fb99600ba9800b80157 }


condition:
	$a0
}