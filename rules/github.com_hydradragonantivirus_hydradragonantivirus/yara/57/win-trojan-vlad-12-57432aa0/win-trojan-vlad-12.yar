rule Win_Trojan_VLAD_12
{
strings:
	$a0 = { 8cc80bc07411e977005b4d656761537465616c74685d0033c0be007cfa8ed08be6fb8ec08ed8832e130402cd12b106 }


condition:
	$a0
}