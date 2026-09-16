rule Win_Trojan_Youth_2
{
strings:
	$a0 = { 40bae804b9e803e8c6fe72b83bc175b4b8004233c933d2e8b6feb440b9e803ba0001e8abfe8026 }


condition:
	$a0
}