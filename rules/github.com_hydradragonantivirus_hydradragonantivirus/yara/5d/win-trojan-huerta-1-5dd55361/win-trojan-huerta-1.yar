rule Win_Trojan_Huerta_1
{
strings:
	$a0 = { 8b1e6101a06301b44024023c02751a33c9525f8a053c0074044147ebf6cd21720a39c87409 }


condition:
	$a0
}