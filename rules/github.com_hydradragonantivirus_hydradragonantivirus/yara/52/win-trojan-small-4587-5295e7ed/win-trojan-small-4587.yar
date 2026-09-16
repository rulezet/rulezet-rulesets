rule Win_Trojan_Small_4587
{
strings:
	$a0 = { 684436f200f8732bf7db8d049effe0b8979e40006a00ff1069d000000100b8000000008d }


condition:
	$a0
}