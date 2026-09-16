rule Win_Trojan_Gen_236
{
strings:
	$a0 = { 60a9ed26d9084dec07c9bbc9f835bd8305c9a1bffacbfcf3cbfef7438ec7f80a5bc616c6c3 }


condition:
	$a0
}