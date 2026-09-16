rule Win_Trojan_Lucky_2
{
strings:
	$a0 = { ffcd213dffee743833c08ec026a18600268b1e84002ea3de012e891edc01e880002e8b169e01b426cd212ea19e01 }


condition:
	$a0
}