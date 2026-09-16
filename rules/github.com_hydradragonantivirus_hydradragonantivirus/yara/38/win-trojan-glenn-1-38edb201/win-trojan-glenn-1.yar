rule Win_Trojan_Glenn_1
{
strings:
	$a0 = { ef009a0d008d005589e5b800039acd02ef0081ec00038dbe00ff1657bffd020e579a30016600bf02030e579a48 }


condition:
	$a0
}