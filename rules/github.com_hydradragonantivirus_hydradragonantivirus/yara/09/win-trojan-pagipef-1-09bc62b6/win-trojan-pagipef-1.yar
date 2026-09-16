rule Win_Trojan_Pagipef_1
{
strings:
	$a0 = { e90000000068000600006a00e8c6ffffffa2??864000c3ccff25b8524000ff25a05140008d8d44feffffe9d6c8ffffb810564000e9??fbffffcccccc8b4df0e9??f9ffff }


condition:
	$a0
}