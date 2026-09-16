rule Win_Spyware_WOW_28
{
strings:
	$a0 = { abda7ca9cc9d267af0bef3fb112f2da1983754192b82183f4a9761d763d494ff255fa58afc23d72656b740fadd88bcf5c0141c409d03942969aff72148b4ffe1e43634e8 }


condition:
	$a0
}