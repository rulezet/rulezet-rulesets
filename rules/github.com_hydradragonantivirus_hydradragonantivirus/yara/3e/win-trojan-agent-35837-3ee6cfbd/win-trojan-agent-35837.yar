rule Win_Trojan_Agent_35837
{
strings:
	$a0 = { 81ec980100005355568b355ca0400057ffd68b1d60a04000ffd3ff1548a04000ff1568a04000ff1550a040 }


condition:
	$a0
}