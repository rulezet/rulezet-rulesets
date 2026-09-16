rule Win_Trojan_RanDir_2
{
strings:
	$a0 = { 465d042e636f6d042e6578655589e581ec0402b80800509ae90c6100408846febfd8000e57bf }


condition:
	$a0
}