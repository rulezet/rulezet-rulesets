rule Win_Trojan_SillyC_112
{
strings:
	$a0 = { 04d3eb8cca03da83eb208edb33d28ec2be00028bfe26803de8742d909090b9e000f3a4061ffa8bca871686008916 }


condition:
	$a0
}