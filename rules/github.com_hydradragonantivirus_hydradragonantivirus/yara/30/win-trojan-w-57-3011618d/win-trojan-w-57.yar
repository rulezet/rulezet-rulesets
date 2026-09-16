rule Win_Trojan_W_57
{
strings:
	$a0 = { e8000000005d8bc52d050003005081ed05004400fc8d85610644005068ff }


condition:
	$a0
}