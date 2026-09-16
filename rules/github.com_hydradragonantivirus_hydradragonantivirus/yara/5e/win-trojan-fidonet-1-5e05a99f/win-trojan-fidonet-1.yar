rule Win_Trojan_Fidonet_1
{
strings:
	$a0 = { 57bf46031e579a4200a000bfc6021e578dbe00ff1657bfb4011e579ab50dcc00bf06001e }


condition:
	$a0
}