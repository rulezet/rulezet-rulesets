rule Win_Trojan_Bancos_659
{
strings:
	$a0 = { 7d0423f26945280b56257e809f54f5caac0dd0885d039cf72ae10c44b825fe418dc6780de4f17392b5dc250c75e20dac446d9bb3df8873fc349ef1f7df9d556325cc1e0c }


condition:
	$a0
}