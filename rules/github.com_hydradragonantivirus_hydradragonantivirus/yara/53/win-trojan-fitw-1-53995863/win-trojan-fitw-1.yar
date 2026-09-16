rule Win_Trojan_Fitw_1
{
strings:
	$a0 = { b84554cd133d544574240e0733c08ed8be4c00bf3301fca5a58cc88ed8ba8000b90100b80102bb740fe8 }


condition:
	$a0
}