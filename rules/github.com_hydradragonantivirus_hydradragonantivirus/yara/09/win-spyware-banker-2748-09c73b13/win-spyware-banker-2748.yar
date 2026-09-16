rule Win_Spyware_Banker_2748
{
strings:
	$a0 = { a1de4913b4cb68c5b460274d9265a1de493d2cb3710b47baceabe8e775e6be2cf0924e6f8bcf0676c5e02b5b9861269ae660587faf7b296cfdcf35dd6106855b001a1eb3e6fd4e8acd1894e28249 }


condition:
	$a0
}