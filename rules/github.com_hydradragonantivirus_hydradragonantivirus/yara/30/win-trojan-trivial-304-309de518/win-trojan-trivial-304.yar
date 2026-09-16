rule Win_Trojan_Trivial_304
{
strings:
	$a0 = { b82600b8023dba9e00cd21b7b5b74093ba0201b13481c3da0081ebda00cd21e90000c32a2e2a }


condition:
	$a0
}