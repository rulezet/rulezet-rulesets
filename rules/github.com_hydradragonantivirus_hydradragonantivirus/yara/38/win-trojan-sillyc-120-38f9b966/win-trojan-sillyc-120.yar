rule Win_Trojan_SillyC_120
{
strings:
	$a0 = { d6b90300cd21b8024233d22bc9cd218bd78bf283c610050001890483c603b440b9e600cd21 }


condition:
	$a0
}