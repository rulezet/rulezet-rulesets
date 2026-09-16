rule Win_Trojan_E_12
{
strings:
	$a0 = { 80fc03743280fc0275289c2eff1e7c01721f26813feb7e751826c7074d5a575150b9150133c08bfb81c78000f3aa }


condition:
	$a0
}