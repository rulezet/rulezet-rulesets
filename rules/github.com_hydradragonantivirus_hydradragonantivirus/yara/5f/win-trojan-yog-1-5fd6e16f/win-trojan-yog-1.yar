rule Win_Trojan_Yog_1
{
strings:
	$a0 = { 5b90b229b91a039030570f4390e2f979a8c2342a7a777fa8ef682b962928902a29da8d91081ce408a5e914e9b6 }


condition:
	$a0
}