rule Win_Trojan__0691_0001_003_1
{
strings:
	$a0 = { b9ae07300446e2fbb440b9ae07bad007cd21e87900bfb207b91e005157b92800e8da03be4407 }


condition:
	$a0
}