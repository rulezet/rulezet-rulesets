rule Win_Trojan_Agent_32962
{
strings:
	$a0 = { 339e2dcc5f2b7d40663b305e6d5bfc748cc4110f54f4cd1a0f9bf48e42b67aacc14279884fa0538a07aa3c66c10f7e58758d397cbfcb2efbaab7670c688ce8623a694a60722ad183354d3f0f5f41 }


condition:
	$a0
}