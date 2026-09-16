rule Win_Trojan_Artem_1
{
strings:
	$a0 = { 8cc88ed88c0673098c16710989266f098ed0bc560afba16109be4601b93f09c6060f0130e8 }


condition:
	$a0
}