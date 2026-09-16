rule Win_Trojan_Sometrouble_1
{
strings:
	$a0 = { c05a595964891068eb7240008d8518feffffba07000000e8f9c5ffffc3e96bc0ffffebe85f5e5b8be55dc30000ffffffff0b0000006c6f616477696e2e62617400ffffffff0900000040454348 }


condition:
	$a0
}