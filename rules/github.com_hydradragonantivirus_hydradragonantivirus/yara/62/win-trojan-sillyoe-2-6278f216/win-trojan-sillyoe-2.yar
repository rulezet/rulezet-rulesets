rule Win_Trojan_SillyOE_2
{
strings:
	$a0 = { 4eba0000b92700cd21721b1e0607b8023dba2400cd21931fb440b97602ba3100cd21b43ecd21b8 }


condition:
	$a0
}