rule Win_Spyware_Banker_3378
{
strings:
	$a0 = { 09e832887870a4b8c820830cd0eccc9a0ccb2683aa1d2231bfab08180fcbb5e7d47830057d63715da5203fa4c9db6cd402d42d431c1233e3983cbdee7b7e32d3ac36d6e5eafd }


condition:
	$a0
}