rule Win_Trojan_Bob_6
{
strings:
	$a0 = { 56019a0000f4005589e5b8000c9a7c02560181ec000cbf7c541e57bf80541e57bf7e541e57bf88541e579a0000 }


condition:
	$a0
}