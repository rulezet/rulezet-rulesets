rule Win_Trojan_VGEN_247
{
strings:
	$a0 = { b9590181374b3083ebfee2f790a3304b6dcadd503178f0c5e88f36db3065bccdf5481ec2b68c33c6a63032c226 }


condition:
	$a0
}