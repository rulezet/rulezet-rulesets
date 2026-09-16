rule Win_Spyware_Goldun_148
{
strings:
	$a0 = { 657284dee410f6252a32457573dcd97f218c736f70686f0e6953d95b16c025ae0d202c }


condition:
	$a0
}