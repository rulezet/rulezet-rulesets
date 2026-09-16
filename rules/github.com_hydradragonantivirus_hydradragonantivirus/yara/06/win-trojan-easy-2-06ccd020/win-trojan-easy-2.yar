rule Win_Trojan_Easy_2
{
strings:
	$a0 = { fb771e3dd2047219a32800b440b1c8e865ff720da12300e85bffb440b226e858ffb43ee84fff }


condition:
	$a0
}