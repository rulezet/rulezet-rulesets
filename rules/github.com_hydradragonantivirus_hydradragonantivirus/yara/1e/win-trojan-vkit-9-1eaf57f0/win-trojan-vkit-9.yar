rule Win_Trojan_VKit_9
{
strings:
	$a0 = { 2e89166503b430cd218b2e02008b1e2c008edaa3093b8c06073b891e033b892e1f3be85a01c43e013b8bc78bd8b9 }


condition:
	$a0
}