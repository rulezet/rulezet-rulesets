rule Win_Trojan_Daniel_5
{
strings:
	$a0 = { c740183f000f00b101ba203246008b03e8ecf8ffff8d55ec33c0e80ef8f9ff8b4decba583246008b03e8f7f9ffff8b03e838f8ffff33c05a59596489106811324600 }


condition:
	$a0
}