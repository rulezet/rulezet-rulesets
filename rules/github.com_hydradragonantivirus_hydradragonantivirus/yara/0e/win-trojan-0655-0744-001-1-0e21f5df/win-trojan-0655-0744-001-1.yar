rule Win_Trojan__0655_0744_001_1
{
strings:
	$a0 = { b90000ba0000cd218d963703b90400b440cd218b8eb6038b96b803b80157cd21b43ecd215ab801 }


condition:
	$a0
}