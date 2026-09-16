rule Win_Spyware_63441_1
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d1085f67509833d }

	$a1 = { 5375626a6563743a }

	$a2 = { 5c5c2e5c5644484350 }

	$a3 = { 50444e533a[0-5]495000000a }


condition:
	$a0 and $a1 and $a2 and $a3
}