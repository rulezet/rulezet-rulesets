rule Win_Trojan_Mpoc_2
{
strings:
	$a0 = { 3e8b9616043e8b8e1404b80157cd218d961c043e8a8e1304b80143cd21b43ecd15b44fe941ff }


condition:
	$a0
}