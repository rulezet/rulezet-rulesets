rule Win_Trojan_Hare_2
{
strings:
	$a0 = { 33c98ed1bc007cb3b1be157c36281c46fec378f8ac7fc5e1beb668be8c9a497c71c671408ed5c189c39447b1 }


condition:
	$a0
}