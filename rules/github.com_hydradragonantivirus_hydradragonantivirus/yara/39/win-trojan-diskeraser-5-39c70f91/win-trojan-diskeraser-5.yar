rule Win_Trojan_DiskEraser_5
{
strings:
	$a0 = { 33c0b91000fa99cd26fbb8004ccd21000000000000496e7465726e65742050686f6e652043726163 }


condition:
	$a0
}