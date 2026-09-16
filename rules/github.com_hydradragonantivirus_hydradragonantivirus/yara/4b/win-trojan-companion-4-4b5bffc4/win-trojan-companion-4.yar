rule Win_Trojan_Companion_4
{
strings:
	$a0 = { 958bd81eb97400b44033ed8eddbae001cd95b43ecd }


condition:
	$a0
}