rule Win_Trojan_Kein_1
{
strings:
	$a0 = { d60032f6b101ca020080fa797714268b4716b6013c037303b103c33c077303b105c3b10ec3 }


condition:
	$a0
}