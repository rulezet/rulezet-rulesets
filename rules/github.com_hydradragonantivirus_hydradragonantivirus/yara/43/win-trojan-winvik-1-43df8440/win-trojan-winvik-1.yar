rule Win_Trojan_WINVIK_1
{
strings:
	$a0 = { 42cd2159b43f8bd5cd215a595081c2690483d100b80042cd2159b4408bd5cd21585a593d0002 }


condition:
	$a0
}