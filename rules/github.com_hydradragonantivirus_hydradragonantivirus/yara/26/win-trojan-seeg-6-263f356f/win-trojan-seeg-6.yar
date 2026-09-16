rule Win_Trojan_Seeg_6
{
strings:
	$a0 = { 6217d6fb46e47c89568f27de95fdf9d207d35c5c55d6d6aceea5e8f685370a8485f642f8af322cf6 }


condition:
	$a0
}