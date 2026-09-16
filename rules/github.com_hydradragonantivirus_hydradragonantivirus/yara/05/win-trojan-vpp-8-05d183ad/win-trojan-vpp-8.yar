rule Win_Trojan_Vpp_8
{
strings:
	$a0 = { 9c601ee800008bec836e16038b7e165d06b82135cd213e899e6c023e8c866e0206533e89a6d9023e8c96db }


condition:
	$a0
}