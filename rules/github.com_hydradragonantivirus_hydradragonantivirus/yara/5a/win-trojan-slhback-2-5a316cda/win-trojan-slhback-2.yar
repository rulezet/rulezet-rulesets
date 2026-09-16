rule Win_Trojan_SlhBack_2
{
strings:
	$a0 = { 686c7c00106a006a00e8adb4ffffa388930010e813b5ffff3db7000000751ea18893001050e869b5ffffa18893001050ff157c9600106a00e8aeb4ffff }


condition:
	$a0
}