rule Win_Trojan_Forth_1
{
strings:
	$a0 = { 0268011ea501e902c801e1029b0185faeb0a2c02f0050e02170600ff8cc88ed08ed88d3603018b }


condition:
	$a0
}