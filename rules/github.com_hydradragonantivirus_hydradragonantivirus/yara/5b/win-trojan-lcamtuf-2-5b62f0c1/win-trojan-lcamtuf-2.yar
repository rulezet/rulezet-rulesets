rule Win_Trojan_Lcamtuf_2
{
strings:
	$a0 = { d700100642fe0595720d2bc47309f7d83b4014063a00721eca182afeba040033d28bdc1e36c47f }


condition:
	$a0
}