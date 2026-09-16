rule Win_Trojan_DNSChanger_197
{
strings:
	$a0 = { 55508adb9f8d6424fc891c2481c3c737c6d05b9e8bff588bec508ac99f575f9e89ed5883ec3cff750858ff700c }


condition:
	$a0
}