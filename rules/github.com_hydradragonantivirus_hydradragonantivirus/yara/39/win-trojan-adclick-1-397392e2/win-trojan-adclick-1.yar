rule Win_Trojan_AdClick_1
{
strings:
	$a0 = { 7009d15e01fc45006e637279707465643b2062f378537f6ff42f1f5543465f2dde50de77c3724c61 }


condition:
	$a0
}