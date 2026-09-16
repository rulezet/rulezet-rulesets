rule Win_Trojan_Hupigon_1549
{
strings:
	$a0 = { 3fcaf83c1e2a8653fdfe0a899d43fc3b7b78b71ff3e8e571a18d516e6c67b125b7bf6917f53e4fb3617dde7ef6839ccfcf829b5f341f992d09781854a3c41471d5f3729d8412091ccdbb5a63dbb6 }


condition:
	$a0
}