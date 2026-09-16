rule Win_Trojan_Hupigon_750
{
strings:
	$a0 = { 95131fbdf6d550ddaf1b5a5426fdb1cf39a3c473b91871b5d8160b6a5df2c73959c83ecc364e0f9bccfc365cbba64f5304d102132b05659f76de951423571dee8f02fb27b2d39bfee8bff3a9f51f }


condition:
	$a0
}