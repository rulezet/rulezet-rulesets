rule Win_Trojan_W_145
{
strings:
	$a0 = { 8bd4cd2effe7663d4e71755660c8001100bec108f7bf66b8023dff16724293b5108bd4b43fff168b4a3c3bc8732e03ca }


condition:
	$a0
}