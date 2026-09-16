rule Win_Trojan_Mybot_5517
{
strings:
	$a0 = { 47c817c5f03ca02851dc01abd8996ec7840924e40359b3a797f8befeb68d2a6bf4f181f60dd91dc47d49f7891812cfd0590c9d6fdcb24e306103dbf172f0c35ce30c087c35fa }


condition:
	$a0
}