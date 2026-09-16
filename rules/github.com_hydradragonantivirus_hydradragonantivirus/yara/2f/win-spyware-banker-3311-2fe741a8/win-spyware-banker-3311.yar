rule Win_Spyware_Banker_3311
{
strings:
	$a0 = { 4864fff088df88d49d86766c4240c6c33ed3caa0acb38dddd527a65ef1d43a74bccb6ab18d7889cf60338414ecfdada5636c1d9bbc88892be13f81ee0d13fd00e79d6cf3a56a }


condition:
	$a0
}