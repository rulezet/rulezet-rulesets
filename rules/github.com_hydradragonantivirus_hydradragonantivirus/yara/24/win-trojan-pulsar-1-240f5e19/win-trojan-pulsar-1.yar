rule Win_Trojan_Pulsar_1
{
strings:
	$a0 = { 023dcd2193c3b80042998b0ef60287cacd21c3b440cd21c3b43fba1b03b91b02cd21c3b0018b0e }


condition:
	$a0
}