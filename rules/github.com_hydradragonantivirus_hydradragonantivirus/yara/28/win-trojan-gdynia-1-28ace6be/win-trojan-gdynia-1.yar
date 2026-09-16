rule Win_Trojan_Gdynia_1
{
strings:
	$a0 = { 2e8a0732c12ac12e880743e2f3b409cd2161c3602e }


condition:
	$a0
}