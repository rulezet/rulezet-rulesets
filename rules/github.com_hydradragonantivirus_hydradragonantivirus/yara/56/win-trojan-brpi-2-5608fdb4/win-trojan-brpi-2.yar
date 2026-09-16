rule Win_Trojan_BrPI_2
{
strings:
	$a0 = { 8916e503b000e805ffb440b91800bae303cd50b002e8f6fe0e1fb440b92b02ba0002cd505a }


condition:
	$a0
}