rule Win_Trojan_Supervisor_2
{
strings:
	$a0 = { b4400e1f2e8b1e2100ba45079c2eff1e17007303e9a9002ea13f07b104d3e80510002ea32300 }


condition:
	$a0
}