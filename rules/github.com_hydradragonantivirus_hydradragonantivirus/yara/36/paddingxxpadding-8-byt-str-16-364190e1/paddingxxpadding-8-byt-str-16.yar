rule PADDINGXXPADDING__8_byt_STR_16_
{
strings:
	$a0 = { 50414444494e47585850414444494e47 }

condition:
	$a0
}