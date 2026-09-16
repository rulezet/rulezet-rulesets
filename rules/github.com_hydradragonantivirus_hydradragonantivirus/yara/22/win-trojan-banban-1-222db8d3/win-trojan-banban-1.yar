rule Win_Trojan_BanBan_1
{
strings:
	$a0 = { 1d817f1e41747416b111890e2500b80103cd6a7209b8010333dbb101cd6abf340033db5307 }


condition:
	$a0
}