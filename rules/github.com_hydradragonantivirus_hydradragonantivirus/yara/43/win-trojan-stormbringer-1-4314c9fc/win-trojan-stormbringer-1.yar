rule Win_Trojan_Stormbringer_1
{
strings:
	$a0 = { b8003dba????cd217303e9870093ba????b90400b43fcd21b43ecd21a1????32e080fc1774110e07bf }


condition:
	$a0
}