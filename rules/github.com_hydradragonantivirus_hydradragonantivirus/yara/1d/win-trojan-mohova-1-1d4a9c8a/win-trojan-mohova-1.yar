rule Win_Trojan_Mohova_1
{
strings:
	$a0 = { 0300f9f3a6c331c989cab80042cd21b80057cd215152bf9a02be930239dd743a8b45012d320250 }


condition:
	$a0
}