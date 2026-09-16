rule Win_Trojan_Broadcast_1
{
strings:
	$a0 = { 088086ac14674d79f8cc4a95819999f61a86c299519898257366c8d5ba0e9c824499eb4dc366ba1a9263a00ba94d }


condition:
	$a0
}