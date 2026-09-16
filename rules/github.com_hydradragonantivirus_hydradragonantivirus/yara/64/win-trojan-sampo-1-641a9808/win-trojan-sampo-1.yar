rule Win_Trojan_Sampo_1
{
strings:
	$a0 = { 8cc88ed88ed0bc00f08bc883c106a11304bb00028bd025 }


condition:
	$a0
}