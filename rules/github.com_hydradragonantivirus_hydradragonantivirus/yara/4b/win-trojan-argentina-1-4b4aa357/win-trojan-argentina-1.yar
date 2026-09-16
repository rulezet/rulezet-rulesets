rule Win_Trojan_Argentina_1
{
strings:
	$a0 = { 06b605e92ea120012d0300a3b705b8004233c933d2cd21720ab440b90300bab605cd21b80157 }


condition:
	$a0
}