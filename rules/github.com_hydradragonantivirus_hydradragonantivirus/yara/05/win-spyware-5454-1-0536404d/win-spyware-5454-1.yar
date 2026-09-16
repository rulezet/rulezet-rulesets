rule Win_Spyware_5454_1
{
strings:
	$a0 = { 518d0a81c12e2cc15587d15952812c24 }


condition:
	$a0
}