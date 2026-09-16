rule Win_Trojan_SillyOC_32
{
strings:
	$a0 = { 4eba2c01cd21721fb8023dba9e00cd218bd8b440ba0001b9380090cd21b43ecd21b44fcd2173 }


condition:
	$a0
}