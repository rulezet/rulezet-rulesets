rule Win_Trojan_Ziuck_1
{
strings:
	$a0 = { 0ee80000fa5d83ed058bc5052b005033c0068ec026c41e84002e895e272e8c462907b8cc4bea7c31541bfa50b93402 }


condition:
	$a0
}