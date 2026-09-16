rule Win_Trojan_Donbass_2
{
strings:
	$a0 = { b440cd2172173bc8751333c933d2b80042cd21ba2f03b91800b440cd215a59b80157cd21 }


condition:
	$a0
}