rule Win_Trojan_Chemist_3
{
strings:
	$a0 = { 425b53cd21be3d028b0cb44051bb8a038a0734cc880743 }


condition:
	$a0
}