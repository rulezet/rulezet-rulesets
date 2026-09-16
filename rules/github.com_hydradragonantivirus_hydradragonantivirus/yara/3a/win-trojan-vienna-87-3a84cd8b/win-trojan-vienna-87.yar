rule Win_Trojan_Vienna_87
{
strings:
	$a0 = { fc8bf383c619bf0001b90300f3a48bf3b82435cd2133db0653baf20203d6b82425cd211e0706b42fcd218c444a }


condition:
	$a0
}