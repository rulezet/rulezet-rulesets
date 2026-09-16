rule Win_Trojan_Codewar_3
{
strings:
	$a0 = { 740a80fc3d74052eff2e5906601e069133c0e83302 }


condition:
	$a0
}