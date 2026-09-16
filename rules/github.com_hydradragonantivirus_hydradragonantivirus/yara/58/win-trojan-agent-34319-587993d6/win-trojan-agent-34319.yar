rule Win_Trojan_Agent_34319
{
strings:
	$a0 = { 6681a424b0fdffff00006681a424b2fdffff0000818c24b0fdffff4a74000a6681a424c4fdffff00006681a424c6fdffff0000818424c4fdffff1125bfb3c784 }


condition:
	$a0
}