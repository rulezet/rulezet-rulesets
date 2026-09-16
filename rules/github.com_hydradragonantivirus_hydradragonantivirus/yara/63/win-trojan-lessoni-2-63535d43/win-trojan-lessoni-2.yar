rule Win_Trojan_LessonI_2
{
strings:
	$a0 = { 023d8d945001cd21724c93b43fb90400ba2a0103d6cd21 }


condition:
	$a0
}