rule Win_Trojan_C_29
{
strings:
	$a0 = { 0e1f0e07e800005d81ed0900e92f028db625008bfee80200eb09ac93ac21d8aae2f8c38db6bf008dbea30066a566 }


condition:
	$a0
}