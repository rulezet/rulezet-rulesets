rule Win_Trojan_TPVO_5
{
strings:
	$a0 = { 10780f4089450ec60662000ce88802b440b9880d99e894027232e87402b440b91800ba880de8 }


condition:
	$a0
}