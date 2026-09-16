rule Win_Trojan_Dikshev_45
{
strings:
	$a0 = { 652ab44ee800008bd6cd21ba9e00b82e5bf2ae66c705434f4d008bcecd2193b440 }


condition:
	$a0
}