rule Win_Trojan_MZV_1
{
strings:
	$a0 = { 0132c4a24f01b440b94d019cff1e44017214b8004233c9cd21b440b90400ba4c019cff1e4401 }


condition:
	$a0
}