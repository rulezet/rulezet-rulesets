rule Win_Trojan_Kode4_6
{
strings:
	$a0 = { b8023dba9e00cd217303e98c008bd8b457b000cd215152b8 }


condition:
	$a0
}