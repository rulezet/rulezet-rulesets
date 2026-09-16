rule Win_Trojan_Ratboy_1
{
strings:
	$a0 = { 21b8024233d233c9cd21b440b90d018d960401cd21 }


condition:
	$a0
}