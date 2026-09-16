rule Win_Trojan_Vienna_1
{
strings:
	$a0 = { 5051e8??00[1-255]5b83eb??fc8d37bf0001b90300f3a48bf3558bec83ec7cb430cd21 }


condition:
	$a0
}