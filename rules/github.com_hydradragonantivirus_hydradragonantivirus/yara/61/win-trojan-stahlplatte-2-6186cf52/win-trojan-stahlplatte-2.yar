rule Win_Trojan_Stahlplatte_2
{
strings:
	$a0 = { 02ba10011eb8007f8ed8b43fcd21 }


condition:
	$a0
}