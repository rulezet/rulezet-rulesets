rule Win_Dropper_Agent_35557
{
strings:
	$a0 = { 6d735c737461727475705c[0-36]6e676c222e626174 }

	$a1 = { 4072656e2068746d2063723473682e68746d }


condition:
	$a0 and $a1
}