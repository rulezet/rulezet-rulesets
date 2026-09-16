rule Win_Trojan_Cmos24_1
{
strings:
	$a0 = { 1388d0e67030c0e671fec280fa407402ebefea0000ffff }


condition:
	$a0
}