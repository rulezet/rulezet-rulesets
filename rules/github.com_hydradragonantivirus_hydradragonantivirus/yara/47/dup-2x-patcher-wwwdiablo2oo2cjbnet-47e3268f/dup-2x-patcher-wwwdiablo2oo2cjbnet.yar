rule _dUP_2x_Patcher__wwwdiablo2oo2cjbnet_
{
	meta:
		description = "dUP 2.x Patcher --> www.diablo2oo2.cjb.net"
	strings:
		$0 = {8B CB 85 C9 74 ?? 80 3A 01 74 08 AC AE 75 0A 42 49 EB EF 47 46 42 49 EB E9}
	condition:
		$0
}