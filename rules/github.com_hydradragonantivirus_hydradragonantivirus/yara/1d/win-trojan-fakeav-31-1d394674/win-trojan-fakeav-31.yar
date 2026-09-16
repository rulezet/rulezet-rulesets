rule Win_Trojan_Fakeav_31
{
strings:
	$a0 = { 90909090539090905790909090569090e80bfeffff9090906a00e8dbffffff83e85790908db8504841 }


condition:
	$a0
}