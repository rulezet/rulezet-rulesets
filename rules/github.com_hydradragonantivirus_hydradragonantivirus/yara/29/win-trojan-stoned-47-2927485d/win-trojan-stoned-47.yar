rule Win_Trojan_Stoned_47
{
strings:
	$a0 = { 03bb66665307cd13fec6ebf29d071f5f5e5a595b58ca020080fa00741180fa01750f31d28eda }


condition:
	$a0
}