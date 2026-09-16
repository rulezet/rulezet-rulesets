rule Win_Trojan_CED_1
{
strings:
	$a0 = { 40b987028d960301cd217317909090b43ecd21b44f8d965202cd217203e927ffeb0590b43ecd21 }


condition:
	$a0
}