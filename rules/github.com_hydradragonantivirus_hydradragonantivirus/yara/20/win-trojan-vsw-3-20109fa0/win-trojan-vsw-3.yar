rule Win_Trojan_VsW_3
{
strings:
	$a0 = { 31c9ba8000cd13eaf0ff00f0e966012020030303202091a0adaae22d8fa5e2a5e0a1e3e0a3 }


condition:
	$a0
}