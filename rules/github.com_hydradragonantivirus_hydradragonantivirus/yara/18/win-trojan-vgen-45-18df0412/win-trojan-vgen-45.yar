rule Win_Trojan_VGEN_45
{
strings:
	$a0 = { ec9d0bc500005e5681ee0801582d0001a2ff0056b97b0181c629018a2432e0882446d0c8e2f55e8b849a028ab49c }


condition:
	$a0
}