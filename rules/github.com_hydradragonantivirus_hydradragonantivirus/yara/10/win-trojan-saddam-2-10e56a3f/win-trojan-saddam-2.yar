rule Win_Trojan_Saddam_2
{
strings:
	$a0 = { 26ebeda1e40225e0ff051f00a3e402b43db0028cca8eda }


condition:
	$a0
}