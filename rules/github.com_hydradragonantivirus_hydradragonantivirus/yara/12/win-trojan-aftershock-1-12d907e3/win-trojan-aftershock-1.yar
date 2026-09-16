rule Win_Trojan_AfterShock_1
{
strings:
	$a0 = { 44021e57bf44031e579a42009200bfc4021e578dbe00ff1657bfb2011e579ab20bbe00bf06001e }


condition:
	$a0
}