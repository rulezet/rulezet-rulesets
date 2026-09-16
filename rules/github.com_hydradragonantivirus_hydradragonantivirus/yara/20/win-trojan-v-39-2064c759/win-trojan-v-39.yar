rule Win_Trojan_V_39
{
strings:
	$a0 = { 5102fccd21b44abb3600cd21b82135cd21be5102891c8c4402b425ba6001cd21bf5201a12c008ed80e07abaf8cc8abafabafab33f6ad4e91e2fb8bd683 }


condition:
	$a0
}