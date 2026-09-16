rule Win_Trojan_Legs_2
{
strings:
	$a0 = { 038a42835e118d962451b44081883159720e3bc12140721e460875d0eb1e410e8a9801eb334d23 }


condition:
	$a0
}