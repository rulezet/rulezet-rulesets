rule Win_Trojan_Mephisto_11
{
strings:
	$a0 = { 9f028dbe1501b9c50031354747e2fac3e8eaffb9c001cd21e8e2ffc3 }


condition:
	$a0
}