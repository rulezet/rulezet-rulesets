rule Win_Trojan_Gen_14
{
strings:
	$a0 = { 04ba0301e89501b440cd21075fb440b91c00badb05cd21e86c01b440b91a00ba340bcd21b801 }


condition:
	$a0
}