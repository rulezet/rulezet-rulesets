rule Windows_CryptCreateHash__8_byt_STR_16_
{
strings:
	$a0 = { 43727970744372656174654861736800 }

condition:
	$a0
}