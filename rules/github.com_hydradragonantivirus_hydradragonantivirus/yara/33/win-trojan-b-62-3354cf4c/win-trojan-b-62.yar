rule Win_Trojan_B_62
{
strings:
	$a0 = { ba8000bf7672cd13beb2022ec6040033c08ec08ed8b80702a34c008c0e4e00 }


condition:
	$a0
}