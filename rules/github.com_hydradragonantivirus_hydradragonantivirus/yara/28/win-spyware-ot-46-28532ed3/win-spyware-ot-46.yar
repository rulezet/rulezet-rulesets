rule Win_Spyware_ot_46
{
strings:
	$a0 = { 34f7bfa4dbe00020773e5f004764ec61e16e58f84de9c1bde562e2cba0ac18d29db6dc1a3356a2addd4ad277f7ebc2b6f1efb75f5358f829de20ba321c705a25ee2dbf557541c85de55ada0e64355a21c1c18c298f14 }


condition:
	$a0
}