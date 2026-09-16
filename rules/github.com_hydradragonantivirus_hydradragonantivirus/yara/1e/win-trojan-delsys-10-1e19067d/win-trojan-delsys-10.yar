rule Win_Trojan_Delsys_10
{
strings:
	$a0 = { 636f7079202e5c74656d705c73797374656d312e696e69202e5c73 }

	$a1 = { 64656c206e6f7374616c67612e626174 }


condition:
	$a0 and $a1
}