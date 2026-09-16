rule Win_Trojan_Sable_1
{
strings:
	$a0 = { 2f6463632073656e642024312024320d }

	$a1 = { 2f6d736720234d616c6179536578 }


condition:
	$a0 and $a1
}