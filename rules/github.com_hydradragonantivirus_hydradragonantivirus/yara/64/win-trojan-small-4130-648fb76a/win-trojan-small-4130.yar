rule Win_Trojan_Small_4130
{
strings:
	$a0 = { 582bec8c9147b424d4632c8e38aa1e5c17b83fcc1a25988b1d01fd3000c8e18702636f6d112e6578cb84706b7a6837616e1162 }


condition:
	$a0
}