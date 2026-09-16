rule Win_Trojan_Mao_1
{
strings:
	$a0 = { 0143e808002ec5164804b824259c2eff1e4404c3b90500be5f04bfbb03e83ffde866003dd7fb72 }


condition:
	$a0
}