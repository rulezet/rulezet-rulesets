rule Win_Trojan_Packed_109
{
strings:
	$a0 = { 0980d7ed4b01d7edc9dda72e0905d7ed0ddc96e97b1801ef7b1e01edba1c41d3ba0241d1ba0041d7c9dd97adba0641d5 }


condition:
	$a0
}