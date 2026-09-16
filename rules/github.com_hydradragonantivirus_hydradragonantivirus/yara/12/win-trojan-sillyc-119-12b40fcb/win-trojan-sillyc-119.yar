rule Win_Trojan_SillyC_119
{
strings:
	$a0 = { b80242b9ffffbaf9ffcd21b440b9eb008d960301cd21b800422bc999cd21c686ee01e98b8e }


condition:
	$a0
}