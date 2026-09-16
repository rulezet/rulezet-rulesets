rule Win_Trojan_Dotter_2
{
strings:
	$a0 = { 0300e9360233c9e81000b9510f2ea0ad028ae0bbaf02e80600c30bc975fcc343432e8b1755535133edb91000 }


condition:
	$a0
}