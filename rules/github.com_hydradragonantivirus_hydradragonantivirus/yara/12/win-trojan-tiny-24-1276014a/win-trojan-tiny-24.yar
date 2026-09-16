rule Win_Trojan_Tiny_24
{
strings:
	$a0 = { 0657560e59f3a45eba4d01b44ecd217301cbb8023dba9e00cd2193b43f8bd65459cd21803c }


condition:
	$a0
}