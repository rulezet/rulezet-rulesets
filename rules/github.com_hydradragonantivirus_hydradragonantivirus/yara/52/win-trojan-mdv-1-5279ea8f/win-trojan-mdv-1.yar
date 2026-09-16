rule Win_Trojan_MDV_1
{
strings:
	$a0 = { e0005589e5bfc3010e57bfa8241e57b80500509a480ae000bfc9010e57bfae241e57b80500509a480ae000bfa8 }


condition:
	$a0
}