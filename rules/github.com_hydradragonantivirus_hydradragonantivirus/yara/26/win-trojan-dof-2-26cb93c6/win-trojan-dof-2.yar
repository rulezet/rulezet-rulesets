rule Win_Trojan_Dof_2
{
strings:
	$a0 = { 03009095bfc10303fd902e813dc3c37418b9ba0390bf2e00 }


condition:
	$a0
}