rule Win_Trojan_NightFall_2
{
strings:
	$a0 = { b334f49df0776bdcd56a2ae0510e5220a19a1fc6e068dae1360dace9f210d4462f788be3fff0f337a02d54f838b7057eb125fe }


condition:
	$a0
}