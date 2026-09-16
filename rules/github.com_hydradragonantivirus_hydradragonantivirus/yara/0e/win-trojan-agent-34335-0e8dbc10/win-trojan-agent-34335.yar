rule Win_Trojan_Agent_34335
{
strings:
	$a0 = { 509bdfe058682f560000e8550000009f8a99883b1ea2e5c3967592f13c4cfcaf }


condition:
	$a0
}