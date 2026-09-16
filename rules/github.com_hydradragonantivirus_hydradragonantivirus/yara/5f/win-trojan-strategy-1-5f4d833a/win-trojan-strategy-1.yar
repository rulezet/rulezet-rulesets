rule Win_Trojan_Strategy_1
{
strings:
	$a0 = { a68bfd7441b8024233c933d2cd21508b85ce01508b8563028985ce01b440b9e6018d958b00cd21 }


condition:
	$a0
}