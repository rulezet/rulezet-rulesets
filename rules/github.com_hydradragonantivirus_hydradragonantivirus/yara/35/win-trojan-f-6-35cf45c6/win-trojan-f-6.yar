rule Win_Trojan_F_6
{
strings:
	$a0 = { 50b80e001e1f530bdb5b50eb059058eb4090e822002e803e3f030775f5c3 }


condition:
	$a0
}