rule Win_Trojan_Doom_1
{
strings:
	$a0 = { a0028dbe1501b9c50031354747e2fac3e8eaffb9c101cd21e8e2ffc3 }


condition:
	$a0
}