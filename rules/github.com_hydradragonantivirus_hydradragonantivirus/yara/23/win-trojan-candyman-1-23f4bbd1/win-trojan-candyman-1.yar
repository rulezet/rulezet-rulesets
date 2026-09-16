rule Win_Trojan_Candyman_1
{
strings:
	$a0 = { 46601e06e86bfd7264e85efeb440b1188bd6e860fe720ce855feb440b9e70399e852fee839fe07 }


condition:
	$a0
}