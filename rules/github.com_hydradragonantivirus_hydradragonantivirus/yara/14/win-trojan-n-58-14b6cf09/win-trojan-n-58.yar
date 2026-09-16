rule Win_Trojan_N_58
{
strings:
	$a0 = { 539db840008ed8be00788ed08be68b16130083ea0789161300b106d3e28ec2b98b2fba80052ae4cd13b80402cd1372 }


condition:
	$a0
}