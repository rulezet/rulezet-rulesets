rule Win_Trojan_Grog_10
{
strings:
	$a0 = { ad50ad5083ee021e560e1fbe4e01b83201ab8cc8ab52 }


condition:
	$a0
}