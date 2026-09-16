rule Win_Trojan_Duke_6
{
strings:
	$a0 = { 756b652f534d46e82bfdbfac020e57b8210050bf50011e579a42003200833e5c23007525833e6c }


condition:
	$a0
}