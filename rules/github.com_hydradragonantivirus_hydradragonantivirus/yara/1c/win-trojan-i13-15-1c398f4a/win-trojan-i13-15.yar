rule Win_Trojan_I13_15
{
strings:
	$a0 = { e2fab9326ace223e22347554b531ce223d08744cb92236ce228a9fd8038d87da038dd9498fc127a204012e }


condition:
	$a0
}