rule Win_Trojan_Anto_4
{
strings:
	$a0 = { 7f0150b41abad400cd21b44eb90300ba7901cd21b98100724abaf200b8023dcd218bd87234b43fba7ffdcd2152a1ee0050fec4a37f018bf9b8004233d233 }


condition:
	$a0
}