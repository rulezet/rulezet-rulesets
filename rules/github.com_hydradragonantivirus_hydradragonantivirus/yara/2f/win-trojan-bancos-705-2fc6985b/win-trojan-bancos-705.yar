rule Win_Trojan_Bancos_705
{
strings:
	$a0 = { 7a1e245d5c7de3e9948ee24e9bc3999392525b6bb01b3edd982edee6ce05d8b94d385b7aff7568ef464b6c09d907b849e0dc180cc07edd2705b4c4d4c3a6a29dce }


condition:
	$a0
}