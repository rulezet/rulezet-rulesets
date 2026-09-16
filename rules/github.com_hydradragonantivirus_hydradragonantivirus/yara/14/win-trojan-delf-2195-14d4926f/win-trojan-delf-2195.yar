rule Win_Trojan_Delf_2195
{
strings:
	$a0 = { 15f49fe90b071ca934840cf0c04a5b232be6ebd610c4fae0421383c2bb59e02260af0ada3f1d5b75e099110c0832d33863ae81b9717f2e2da163 }


condition:
	$a0
}