rule Win_Trojan__0616_0002_001_1
{
strings:
	$a0 = { 10b800428bcacd21b4408bd7b91800cd215a595840cd21b43ecd215a1f5958cd21585a1fcd }


condition:
	$a0
}