rule Win_Trojan_Virtool_6
{
strings:
	$a0 = { 5589e583ec08c7042401000000ff1520714400e8b8feffff908db426000000005589e5 }

	$a1 = { 544d50005c70726f742e657865 }


condition:
	$a0 and $a1
}