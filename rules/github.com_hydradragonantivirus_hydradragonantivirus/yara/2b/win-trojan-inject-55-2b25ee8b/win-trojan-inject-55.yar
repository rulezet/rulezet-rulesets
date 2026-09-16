rule Win_Trojan_Inject_55
{
strings:
	$a0 = { f97209165a43f30c7a47fd1d509bdfe0 }

	$a1 = { 41747570527072707243676f6561707044736564616365526e42 }


condition:
	$a0 and $a1
}