rule Win_Trojan_Deltree_24
{
strings:
	$a0 = { 44454c5452454500132f7920433a5c446f63756d657e315c2a2e2a }


condition:
	$a0
}