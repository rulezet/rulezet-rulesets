rule Win_Trojan_Unnamed_8
{
strings:
	$a0 = { 0156b80103b90900cd13b801038d9e0001b90100cd13c350568bf2ac3c2e74070ac075f7 }


condition:
	$a0
}