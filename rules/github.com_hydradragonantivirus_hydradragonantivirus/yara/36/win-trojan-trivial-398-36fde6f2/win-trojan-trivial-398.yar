rule Win_Trojan_Trivial_398
{
strings:
	$a0 = { 9246b4614781ea8d9180f42fcd21ba64aab8c35781f2faaa4e2dc11a4dcd21f9baff2481eaff }


condition:
	$a0
}