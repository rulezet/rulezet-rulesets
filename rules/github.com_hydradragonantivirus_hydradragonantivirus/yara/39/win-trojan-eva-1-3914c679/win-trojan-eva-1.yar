rule Win_Trojan_Eva_1
{
strings:
	$a0 = { 104c040b0196009702edf60000060e1f8b0e0c008bf14e89f78cdb031e0a008ec3b400 }


condition:
	$a0
}