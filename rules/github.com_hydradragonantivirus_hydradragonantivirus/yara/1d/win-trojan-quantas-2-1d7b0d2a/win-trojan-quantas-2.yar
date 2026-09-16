rule Win_Trojan_Quantas_2
{
strings:
	$a0 = { b85007bf0000be3b02b9d007f3a5c60606125cb447be0712b200cd21b41abadc11cd21b44eba8401b90700eb0db43bba9101cd21722bebebb44fcd2172ef }


condition:
	$a0
}