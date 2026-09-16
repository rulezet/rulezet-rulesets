rule Win_Trojan_Marky_1
{
strings:
	$a0 = { 40b9030089f281c2bd01cd217212b80040b9db0189f2cd21b8003ecd2131c0c3b8003ecd21b8 }


condition:
	$a0
}