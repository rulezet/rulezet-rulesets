rule Win_Trojan_Trivial_344
{
strings:
	$a0 = { 9e00b8423dcd21721593b440ba0001247d4341525e4bb144cd21b43ecd21b44febd82a2e436f4d }


condition:
	$a0
}