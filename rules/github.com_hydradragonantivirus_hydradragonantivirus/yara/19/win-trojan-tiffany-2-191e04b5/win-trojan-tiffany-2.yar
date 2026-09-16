rule Win_Trojan_Tiffany_2
{
strings:
	$a0 = { fc368b3583ee03b9e500565d061e0e0e071f83bc9100007514fc8db4c601b8002fcd152d0085972bc0a5a58bf5998e }


condition:
	$a0
}