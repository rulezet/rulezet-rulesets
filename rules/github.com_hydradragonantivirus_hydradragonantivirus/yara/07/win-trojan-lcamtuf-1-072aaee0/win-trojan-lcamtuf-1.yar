rule Win_Trojan_Lcamtuf_1
{
strings:
	$a0 = { 5d7c3515ded995a3f974880aee315c04e3e358b39b3904d9a9d0347a5ae6f8f26905e85c5f58 }


condition:
	$a0
}