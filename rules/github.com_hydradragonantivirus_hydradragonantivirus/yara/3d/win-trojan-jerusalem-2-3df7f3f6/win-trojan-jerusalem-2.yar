rule Win_Trojan_Jerusalem_2
{
strings:
	$a0 = { b80042cd21720ab91c00ba0402b440cd2172133bc1751b2e8b16e6012e8b0ee801b80042cd }


condition:
	$a0
}