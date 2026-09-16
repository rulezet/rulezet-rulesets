rule Win_Trojan_Stoned_54
{
strings:
	$a0 = { 567c33ff8b1e13044b891e1304b90602d3e3891e9f7c8ec3c7064c003600891e4e00f3a4eaa1 }


condition:
	$a0
}