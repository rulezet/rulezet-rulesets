rule Win_Trojan_Emdivi_1
{
strings:
	$a0 = { 26646174653d3f }

	$a1 = { 5645523a }

	$a2 = { 097c094e543a }

	$a3 = { 097c094d454d3a2025644d }

	$a4 = { 097c09474d5428 }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}