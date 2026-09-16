rule Win_Trojan_SillyC_127
{
strings:
	$a0 = { b903008d94eb00cd21b8024233c933d2cd21b440b9ef008d54fdcd215a5980c91fb80157cd21 }


condition:
	$a0
}