rule Win_Trojan_CVM_1
{
strings:
	$a0 = { 2e8a56078bf58bfd0e588ed88ec0b92a05ac32c2aae2fa }


condition:
	$a0
}