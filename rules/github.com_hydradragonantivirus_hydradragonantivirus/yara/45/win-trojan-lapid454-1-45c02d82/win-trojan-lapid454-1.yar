rule Win_Trojan_LAPID454_1
{
strings:
	$a0 = { 96ca01cd21b8024233c933d2cd21b440b912008d96db01cd21b440b9b4018d961200cd21b80157 }


condition:
	$a0
}