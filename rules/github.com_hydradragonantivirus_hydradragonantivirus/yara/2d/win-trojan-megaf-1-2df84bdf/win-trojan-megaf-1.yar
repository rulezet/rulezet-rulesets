rule Win_Trojan_MegaF_1
{
strings:
	$a0 = { ffcd213d34567503e9bc00b82135cd212e891e3d042e8c063f04b81335cd212e891e6d012e8c066f0131c08e }


condition:
	$a0
}