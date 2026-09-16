rule Win_Trojan_Five_1
{
strings:
	$a0 = { 5a74bbb002e85400ba6103b96102b440cd21e8370032c0e84200ba0001b96102b440cd218b16 }


condition:
	$a0
}