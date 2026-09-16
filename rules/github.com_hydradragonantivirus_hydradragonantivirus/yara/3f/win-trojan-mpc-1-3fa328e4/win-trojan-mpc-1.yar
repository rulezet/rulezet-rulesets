rule Win_Trojan_MPC_1
{
strings:
	$a0 = { b903008d969801cd21b002e81b00b440b996008d960301cd21b43ecd21b44f }


condition:
	$a0
}