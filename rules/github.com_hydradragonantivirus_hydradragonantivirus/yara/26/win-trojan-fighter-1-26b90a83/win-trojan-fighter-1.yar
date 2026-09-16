rule Win_Trojan_Fighter_1
{
strings:
	$a0 = { 0e81e71c2d02b9b3404b87f625ff5b81c0a788c6c7c58b78ba31c087db81cefffff801c081cdffff740887f62afb8b }


condition:
	$a0
}