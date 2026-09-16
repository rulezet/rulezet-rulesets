rule Win_Trojan_Slazlcen_1
{
strings:
	$a0 = { e8000000005f558bc783e8052d004200005650eb05 }

	$a1 = { 5f5781c70042000083c7438bdf83eb2eb92206000033c08a17321418 }


condition:
	$a0 and $a1
}