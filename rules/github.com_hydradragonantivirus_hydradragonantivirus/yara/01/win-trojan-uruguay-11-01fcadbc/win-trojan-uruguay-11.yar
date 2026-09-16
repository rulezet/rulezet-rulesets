rule Win_Trojan_Uruguay_11
{
strings:
	$a0 = { bd2bb04d1a5d62c285caf61db370f1d7f0792b530d5bab10079dc46bc3c2453a94b2ac6e97cec01796a42a2796a1cc5f72adf2e9a1 }


condition:
	$a0
}