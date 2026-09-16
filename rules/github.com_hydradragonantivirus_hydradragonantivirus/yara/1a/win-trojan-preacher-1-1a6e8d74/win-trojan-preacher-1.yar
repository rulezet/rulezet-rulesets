rule Win_Trojan_Preacher_1
{
strings:
	$a0 = { 01cd218bd87300b4402e8b0e0f01badb02cd21b43ecd218cc82ea331012ea335012ea33901b8 }


condition:
	$a0
}