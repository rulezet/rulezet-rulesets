rule Win_Trojan_Ugly_1
{
strings:
	$a0 = { 17bc007c0e1fb91b01bb157c5180376643e2fa }


condition:
	$a0
}