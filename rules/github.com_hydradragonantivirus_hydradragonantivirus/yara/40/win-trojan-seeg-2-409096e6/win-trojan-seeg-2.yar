rule Win_Trojan_Seeg_2
{
strings:
	$a0 = { 3e771d4affc9501ca50392a67fadc558289718e294115ab4bc938d5e7867c0f024d5029aff7348ae }


condition:
	$a0
}