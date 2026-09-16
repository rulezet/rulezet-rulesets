rule Win_Dropper_Agent_33951
{
strings:
	$a0 = { b82cab4000e801feffff683cab40008d45f0e890feffffff75f0680cab4000b8bcc54000ba03000000e88988ffff6a006a00a1bcc54000e87f89ffff506840ab4000684cab40006a00e851feffff }


condition:
	$a0
}