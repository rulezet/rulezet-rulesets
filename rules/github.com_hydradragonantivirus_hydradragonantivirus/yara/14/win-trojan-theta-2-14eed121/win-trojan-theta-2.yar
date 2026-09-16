rule Win_Trojan_Theta_2
{
strings:
	$a0 = { e800005e83ee03b87730cd21fc1ee3281f1e072e80bcf9014d75121e580510002e03840f02502e8b840d0250cbbf0001 }


condition:
	$a0
}