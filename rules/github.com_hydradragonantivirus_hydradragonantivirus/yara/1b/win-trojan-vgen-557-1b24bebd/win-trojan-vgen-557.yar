rule Win_Trojan_VGEN_557
{
strings:
	$a0 = { 3e0600268b4503e86c00be870103f51e0e1f8904b82135cd21895cfa8c44fcba960103d5b80125cd211f9c580d00 }


condition:
	$a0
}