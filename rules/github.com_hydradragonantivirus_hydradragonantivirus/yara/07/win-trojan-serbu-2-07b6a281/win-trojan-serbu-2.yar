rule Win_Trojan_Serbu_2
{
strings:
	$a0 = { 5f89e58db56401bf2b00804e01030e565731ff31c98edf5e8f45048f45069de3feebfb82ee }


condition:
	$a0
}