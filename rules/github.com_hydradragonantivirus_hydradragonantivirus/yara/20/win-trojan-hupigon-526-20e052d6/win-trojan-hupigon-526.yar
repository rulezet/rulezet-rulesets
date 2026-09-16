rule Win_Trojan_Hupigon_526
{
strings:
	$a0 = { c473c918ce454e35fcf89ee7230fe005d03e3dfe761baa62a3a99c25c61b7a714e3891bc469fb4e12b5f295419e7aaf6198b0a9ad05d0675341a7eccb3f781c79556a9f2260e711ce4fb298e5d28 }


condition:
	$a0
}