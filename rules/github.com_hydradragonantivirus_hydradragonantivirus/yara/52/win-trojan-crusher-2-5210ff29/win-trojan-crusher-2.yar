rule Win_Trojan_Crusher_2
{
strings:
	$a0 = { 40019a0d00de005589e531c09acd024001e8b7f4e833f7e80af9e80bfbe894f5e859fcb8010050e8f8f4bf5a10 }


condition:
	$a0
}