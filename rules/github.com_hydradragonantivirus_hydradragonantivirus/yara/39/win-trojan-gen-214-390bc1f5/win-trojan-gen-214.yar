rule Win_Trojan_Gen_214
{
strings:
	$a0 = { 65e2feb807000dc0b789f2d0efb007de130140a20c087526a7f80f4ebc6bc5febf43c91b3efc24 }


condition:
	$a0
}