rule Win_Trojan_Life_2
{
strings:
	$a0 = { 1800ba140103d5e8d9fe33c933d2b80242e8cffe53e88bfeb9d105ba000103d55bb440e8bd }


condition:
	$a0
}