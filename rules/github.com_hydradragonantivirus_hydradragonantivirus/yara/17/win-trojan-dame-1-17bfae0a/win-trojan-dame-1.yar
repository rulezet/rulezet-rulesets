rule Win_Trojan_DAME_1
{
strings:
	$a0 = { 4144cd2181fb4847753c1e060e1f33c08d765e8ec033ffb90800f3a77408403d00a072ec }


condition:
	$a0
}