rule Win_Spyware_53879_1
{
strings:
	$a0 = { f0c745f0333630545053c745f47261792e8975fcc745c033363053c745c4 }


condition:
	$a0
}