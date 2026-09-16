rule Win_Trojan_Peed_52
{
strings:
	$a0 = { 8b6c241c83ed2d83ed3281eda00000004883c53c09ed75f2 }


condition:
	$a0
}