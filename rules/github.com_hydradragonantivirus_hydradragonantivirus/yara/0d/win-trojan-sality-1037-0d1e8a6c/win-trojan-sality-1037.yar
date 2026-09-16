rule Win_Trojan_Sality_1037
{
strings:
	$a0 = { 606a8ee8bb05000058e8260000003061d97f6532b5e2707323b17dce7ab165 }

	$a1 = { 3359262936463d1b6c3158 }


condition:
	$a0 and $a1
}