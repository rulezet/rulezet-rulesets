rule Win_Spyware_Banker_2676
{
strings:
	$a0 = { ac2211a81cbdcf99ef7575c6817bf27f5308ba28742ce40c7f7122f2eef22d93ed00085967dadcec3627a6dfb12d6f9fe2b05744346e246a4dece7f42db63dda8da58da49e117bfc7e2e984ff246 }


condition:
	$a0
}