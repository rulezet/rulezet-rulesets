rule Win_Trojan_SillyOC_8
{
strings:
	$a0 = { 4eb120ba8505cd21b8013dba9e00cd2193b440b99e04ba0001cd21b43ecd21b44fcd2173e3e962 }


condition:
	$a0
}