rule Win_Trojan_Trux_1
{
strings:
	$a0 = { fc4d742780fc3f742280fc45741d80fc13741e80fc1474193dff327504bb3412cffeccfecc2eff }


condition:
	$a0
}