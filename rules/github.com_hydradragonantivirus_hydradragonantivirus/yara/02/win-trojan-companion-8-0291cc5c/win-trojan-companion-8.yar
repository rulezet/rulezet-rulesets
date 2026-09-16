rule Win_Trojan_Companion_8
{
strings:
	$a0 = { 5b80f441baac01cd21b44ebeca0133c9884cd390ba9801cd2172208bd6e8c8ffb45bb10449cd2193b44f72dfb440b1 }


condition:
	$a0
}