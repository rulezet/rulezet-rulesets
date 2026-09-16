rule Win_Trojan_Munich_1
{
strings:
	$a0 = { 8eda8d3619008bfeb98e0490065b8ec2ad35 }


condition:
	$a0
}