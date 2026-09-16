rule Win_Spyware_ye_260
{
strings:
	$a0 = { 687dcc4500558bec83ec688d55e4528d45e450ff75f868593474698d45e05051ff75f4e866e9ffffc9c22000687dcc45 }


condition:
	$a0
}