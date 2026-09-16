rule Win_Trojan_Vienna_5
{
strings:
	$a0 = { b904048bd681ea130352515350b4 }


condition:
	$a0
}