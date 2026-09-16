rule Win_Trojan_Trivial_351
{
strings:
	$a0 = { 02dc9090b92000b44eba2201cd21b8023dba9e00cd218bd8b440b94b00ba0001cd21 }


condition:
	$a0
}