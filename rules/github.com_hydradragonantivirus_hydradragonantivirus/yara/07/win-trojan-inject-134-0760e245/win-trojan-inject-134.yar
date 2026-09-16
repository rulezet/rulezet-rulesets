rule Win_Trojan_Inject_134
{
strings:
	$a0 = { 8b463c8d149b03c68bbcd0040100008b8cd00c01000003ce037c24??6a00ffb4d0080100005157ffb424[4]ff5424??8b4424??0fb7543006433bda7cc0 }


condition:
	$a0
}