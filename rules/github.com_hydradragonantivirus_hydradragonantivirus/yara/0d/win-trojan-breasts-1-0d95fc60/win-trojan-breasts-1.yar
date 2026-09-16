rule Win_Trojan_Breasts_1
{
strings:
	$a0 = { 01be207cb9690241a4e2fd832e130410bb39010653cb }


condition:
	$a0
}