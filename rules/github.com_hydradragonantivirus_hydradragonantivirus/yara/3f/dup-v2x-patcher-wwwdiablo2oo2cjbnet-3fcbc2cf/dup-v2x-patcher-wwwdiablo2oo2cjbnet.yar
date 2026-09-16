import "pe"
rule _dUP_v2x_Patcher__wwwdiablo2oo2cjbnet_
{
	meta:
		description = "dUP v2.x Patcher --> www.diablo2oo2.cjb.net"
	strings:
		$0 = {54 68 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F 74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20 6D 6F}
	condition:
		$0 at pe.entry_point
}