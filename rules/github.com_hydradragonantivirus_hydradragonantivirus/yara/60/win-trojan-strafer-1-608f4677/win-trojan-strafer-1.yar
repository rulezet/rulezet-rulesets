rule Win_Trojan_Strafer_1
{
strings:
	$a0 = { 08005a59c3b80102eb03b801035756bf05008bf08bc6e806ff7306e8fffe4f75f35e5fc39c3d01 }


condition:
	$a0
}