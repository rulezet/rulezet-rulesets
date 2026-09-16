rule Win_Trojan_Tutan_1
{
strings:
	$a0 = { 3d73e76e9a3786f5b901f5759b755d158aa12bec2f77d43ebacafecd561634850172b100ba835011 }


condition:
	$a0
}