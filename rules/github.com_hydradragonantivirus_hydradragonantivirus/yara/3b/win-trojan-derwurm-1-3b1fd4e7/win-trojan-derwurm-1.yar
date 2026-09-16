rule Win_Trojan_DerWurm_1
{
strings:
	$a0 = { 028ec126bb720483c30f80e3f026891ef800268c1ef20001e383c30f80e3f08ed189dc26891efa0089dad1ead1 }


condition:
	$a0
}