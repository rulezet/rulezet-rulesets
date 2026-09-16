rule Win_Trojan_VCL_9
{
strings:
	$a0 = { 01b800429933c9cd21b440b903008d96f001cd21b802429933c9cd21b440b9f0008d960301cd21b8 }


condition:
	$a0
}