rule Win_Trojan_R_49
{
strings:
	$a0 = { eb0190b801faba4559cd16e800005d81ed0f01e814018db65102bf000157a5a5b419cd213c017701c38d965b02b41a }


condition:
	$a0
}