rule Win_Trojan_Inside_1
{
strings:
	$a0 = { 0300eb389057bf3a02902e80b51800374f87db75f55fc3 }


condition:
	$a0
}