rule Win_Trojan_Serbu_3
{
strings:
	$a0 = { 511e9cfae800005f89e58db56401bf2b00804e01030e565731ff31c98edf5e8f45048f45069de3feebff01020304 }


condition:
	$a0
}