rule Win_Trojan_Vienna_67
{
strings:
	$a0 = { 40b9d6028bd681eafc01cd21723e3d }


condition:
	$a0
}