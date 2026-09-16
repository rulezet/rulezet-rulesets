rule Win_Adware_Lop_181
{
strings:
	$a0 = { a2000e93b1318258e28ec976d5cef9015969b07bda6b6cf09453f699ba57f4e03ca6af2d3cefe9b412b0c8b3b25ed405fa090726118e006d2310b64b }


condition:
	$a0
}