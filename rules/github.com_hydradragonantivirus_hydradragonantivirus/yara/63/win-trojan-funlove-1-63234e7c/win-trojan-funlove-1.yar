rule Win_Trojan_FunLove_1
{
strings:
	$a0 = { e8000000005b81ebb40a0000c3c8000000ff7508e84dfeffff0bc0740d508db3ab0c000056e8c2feffffc9c204008d83db0e000050e8f00200000bc0740d508d }


condition:
	$a0
}