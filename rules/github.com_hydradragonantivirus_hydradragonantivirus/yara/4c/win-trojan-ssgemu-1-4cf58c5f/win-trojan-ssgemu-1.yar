rule Win_Trojan_SSGemu_1
{
strings:
	$a0 = { 404040400a0d008db62000b82201ffd08db65900b82201ffd08db68b00b82201ffd08db6bd00 }


condition:
	$a0
}