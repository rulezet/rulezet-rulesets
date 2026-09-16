rule Win_Trojan_Timid_3
{
strings:
	$a0 = { e80000832efcff09e831007203e89400ba8000b41acd218b1efcff8b473d90a300018b473f90a302018a474190a20401 }


condition:
	$a0
}