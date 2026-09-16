rule Win_Trojan__0616_0002_000_1
{
strings:
	$a0 = { 02f7f10bd2740140ab92abb44099b99701cd217210b800428bcacd21b4408bd7b91800cd215a59 }


condition:
	$a0
}