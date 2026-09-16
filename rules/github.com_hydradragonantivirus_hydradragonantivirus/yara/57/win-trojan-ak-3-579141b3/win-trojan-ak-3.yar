rule Win_Trojan_AK_3
{
strings:
	$a0 = { 038cc88ed88ec033f68bfd81c76d01fcb95000f3a58bf581c65901bf0001b90500fcf3a4b44eb97f008bd581c2 }


condition:
	$a0
}