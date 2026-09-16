rule Win_Trojan_Vpp_5
{
strings:
	$a0 = { 5a5853502bc22d0300c645ffe88bd74aabb440b90300cd21e871ff8bfeb89c60abba30ffe8 }


condition:
	$a0
}