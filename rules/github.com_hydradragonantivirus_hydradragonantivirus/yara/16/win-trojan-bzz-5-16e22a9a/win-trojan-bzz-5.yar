rule Win_Trojan_Bzz_5
{
strings:
	$a0 = { b440b903008d96e202cd21b002b44233c999cd21b93200be00008dbe1003f3a48bd7be9005 }


condition:
	$a0
}