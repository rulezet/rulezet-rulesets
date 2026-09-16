rule Win_Trojan_Gunia_1
{
strings:
	$a0 = { 4616e848ffb440b940038bd583ea05cd21e839ffb8004233c933d2cd21b440b919008bd5cd21 }


condition:
	$a0
}