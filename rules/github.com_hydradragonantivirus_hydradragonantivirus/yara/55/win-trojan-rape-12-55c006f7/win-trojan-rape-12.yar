rule Win_Trojan_Rape_12
{
strings:
	$a0 = { 2e8b16010181c203018bf28bea83c53255eb00b000563c00741583c632b9b0018a24518ac8d2c4598824fec046e2f1 }


condition:
	$a0
}