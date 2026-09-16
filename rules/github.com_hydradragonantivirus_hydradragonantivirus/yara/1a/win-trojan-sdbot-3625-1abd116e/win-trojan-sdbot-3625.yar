rule Win_Trojan_SdBot_3625
{
strings:
	$a0 = { be2484a9f845e8f3b0fc65141fd6a2f417eb1de80bc574ae606855aea3aeefd2497dbf17524114ffa1cd8da657f2b90f57057e461b79deba4ee050350e5a97e9b1d2cd33b0d838e3baff93fec234 }


condition:
	$a0
}