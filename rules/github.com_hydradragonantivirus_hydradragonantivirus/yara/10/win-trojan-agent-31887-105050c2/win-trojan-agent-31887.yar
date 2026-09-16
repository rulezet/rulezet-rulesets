rule Win_Trojan_Agent_31887
{
strings:
	$a0 = { 6898d0400089f1e8a3fdffff8b40048038317517685cd0400089f1e88ffdffffff7004e89df6ffff59eb06 }


condition:
	$a0
}