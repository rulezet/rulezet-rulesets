rule Win_Trojan_Rukap_67
{
strings:
	$a0 = { b0894acfc9880d1c15de0a059dfe4788438ca6d58c0ecada66754c5bb5db879f5406b71bcb0aa4d6657c5ea5ed8e0c395ff26f5a7551eddb55d19b80f1be99f2f3 }


condition:
	$a0
}