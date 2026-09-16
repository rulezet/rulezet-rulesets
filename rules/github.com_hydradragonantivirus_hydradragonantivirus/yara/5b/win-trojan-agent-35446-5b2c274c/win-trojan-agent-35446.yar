rule Win_Trojan_Agent_35446
{
strings:
	$a0 = { 6a0068e718010068ed170100833c2400750b8d54240c600ee8 }

	$a1 = { 53616665204d6f6e20333630 }


condition:
	$a0 and $a1
}