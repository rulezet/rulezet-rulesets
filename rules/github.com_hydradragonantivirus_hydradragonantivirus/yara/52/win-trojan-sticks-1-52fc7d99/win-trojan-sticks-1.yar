rule Win_Trojan_Sticks_1
{
strings:
	$a0 = { fc368b35b9d80083ee038bee061e0e0e071f83bc9000007514fc8db4ac01b8002fcd152d0085972bc0a5a58bf5998e }


condition:
	$a0
}