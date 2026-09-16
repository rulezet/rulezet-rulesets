rule Win_Trojan_Hal_1
{
strings:
	$a0 = { 8b0cb43fcd21b8004233c999cd2159030c87fab440cd215a59b80157cd21b43ecd2158eb71909c }


condition:
	$a0
}