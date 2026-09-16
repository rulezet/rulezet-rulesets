rule Win_Trojan_R_81
{
strings:
	$a0 = { c802cd21e80100c33e8bb61d018dbe4401b9420131354747e2fac3 }


condition:
	$a0
}