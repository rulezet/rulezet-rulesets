rule Win_Trojan_MiniCommander_1
{
strings:
	$a0 = { 21693c68f0b47029322b6e702b1a17ff0d06110d1116edb615410708050dc851c2060ddefe1e1173ab1d71c21106115b6e0be1dbff35192b491f1c731620ad87 }


condition:
	$a0
}