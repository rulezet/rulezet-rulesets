rule Win_Trojan_Vienna_85
{
strings:
	$a0 = { ad00be9a030e1fe8be005683c60abf0001a5a45e06b42fcd218c4402891c0706b41a8d545fcd211e8b4cfe83e1 }


condition:
	$a0
}