rule Win_Trojan_Serbu_5
{
strings:
	$a0 = { 50b8eb052ceb74fa9ae800005f538db54802bf33001e29c99c89e50e56804e01035731ff8edf }


condition:
	$a0
}