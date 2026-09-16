rule Win_Trojan_Bifrose_178
{
strings:
	$a0 = { 32127e074fa7ab603680f55113571e08f68880b64ea8045fe20e39d3c9ca42022b29e0aabda000ccfbf7affcdcc2b9987180dae5cb00250128f351b7b32a0017fbeceab1 }


condition:
	$a0
}