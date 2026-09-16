rule Win_Trojan_Hupigon_60
{
strings:
	$a0 = { c9793c8b410885c079355033430450ff53 }

	$a1 = { 6765746b65792e646c6c004372656174654f62 }


condition:
	$a0 and $a1
}