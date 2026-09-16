rule Win_Trojan_Anti_8
{
strings:
	$a0 = { be2901417441b8024233c999cd212d03003e89862b01b440b985038d960001cd21b8004233c9 }


condition:
	$a0
}