rule Win_Trojan_Atomic_5
{
strings:
	$a0 = { 962903cd21b9ff1fe2feea0000ffffb41acd21c3b457cd21c3b443cd21c3b442cd21c3 }


condition:
	$a0
}