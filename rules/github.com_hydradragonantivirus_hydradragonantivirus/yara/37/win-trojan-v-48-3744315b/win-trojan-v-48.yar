rule Win_Trojan_V_48
{
strings:
	$a0 = { b4408b1e9f0250558becc7460200905d1f33d2cd211ffe06ac02803eab02dd907406c606ab02ff }


condition:
	$a0
}