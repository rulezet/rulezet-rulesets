rule Win_Trojan_Bancos_985
{
strings:
	$a0 = { a2728c31a6d7ef2cdf5998bfcfd368527568b18334e6debbf33d178de2845dc3071c60509c316d00bd4ccdc9ea42a6119320553167ed108ed4497bae6f7d8fd9 }


condition:
	$a0
}