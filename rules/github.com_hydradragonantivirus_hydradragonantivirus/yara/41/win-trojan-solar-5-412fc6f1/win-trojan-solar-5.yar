rule Win_Trojan_Solar_5
{
strings:
	$a0 = { 40754d8bf2ad3d4d5a7545ad3d8501733f8be9c1ed09 }


condition:
	$a0
}