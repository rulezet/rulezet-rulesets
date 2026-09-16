rule Win_Trojan_Wally_2
{
strings:
	$a0 = { bb5b0129d9a135ff2d040150055b018bf858bed50401c68a04300547e2fbe91b0073c27409 }


condition:
	$a0
}