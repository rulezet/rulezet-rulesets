rule Win_Trojan_LoginTheaf_1
{
strings:
	$a0 = { 4e05b90300b440cd215a33c9b80042cd21ba0001b9ab03b440cd21ba3105b409cd21b8004c }


condition:
	$a0
}