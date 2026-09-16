rule Win_Trojan_Dumador_53
{
strings:
	$a0 = { 0fbae383d1e888f40fb7dbb4091cc58af00fa3d80fbfd764c7c3a3411c490fafc080ef590fabf887c286f4d2db4f4af22e02d8fece84e30fbfc76581ea6dea161dfec30facc3748d3d58e8ba514b0fbfda0fc0 }


condition:
	$a0
}