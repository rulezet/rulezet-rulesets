rule Win_Trojan_Capwin_3
{
strings:
	$a0 = { 9b559b01589262f2367bd32acb9e35f3b906b6d0ebce3445bed06cddc5d77b183650cb202a20c5053efc7242a6831587a4fc1eee0fa2c7d5aa40a82b288364c24ff57db81ef20e1f45a15a1df6a3aa88 }


condition:
	$a0
}