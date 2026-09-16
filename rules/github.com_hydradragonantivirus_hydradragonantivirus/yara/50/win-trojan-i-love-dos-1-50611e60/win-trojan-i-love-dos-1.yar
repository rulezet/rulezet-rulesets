rule Win_Trojan_I_Love_Dos_1
{
strings:
	$a0 = { 0500b8004ccd2150068bec8b760481ee03018cc88ec08ed8b9c30d8d9c3b018a843a012807d0c043e2f98dbc700cb8 }


condition:
	$a0
}