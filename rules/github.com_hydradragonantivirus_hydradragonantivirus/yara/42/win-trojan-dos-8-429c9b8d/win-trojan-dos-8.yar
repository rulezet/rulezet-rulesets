rule Win_Trojan_DOS_8
{
strings:
	$a0 = { 6e20646e2e636667205589e5b8d2099a3005a90081ecd2098cd38ec38cdbfc8d7eb0c57604ac }


condition:
	$a0
}