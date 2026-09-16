rule Win_Trojan_Vienna_71
{
strings:
	$a0 = { 89d6e80200fcc356b9f20129ceacf6d08844ffe2f8 }


condition:
	$a0
}