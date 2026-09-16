rule Win_Trojan_Autorun_204
{
strings:
	$a0 = { 5b6175746f72756e5d0d0a7368656c6c657865637574653d52656379636c65645c }


condition:
	$a0
}