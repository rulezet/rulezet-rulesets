rule Win_Trojan_VB_1686
{
strings:
	$a0 = { 616c697373696d61000b02000360ea000007781e000008c0120000ff0387 }


condition:
	$a0
}