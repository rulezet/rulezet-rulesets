rule Win_Trojan_Q_2
{
strings:
	$a0 = { fa05b9da04ba0401e89501b440cd21075fb440b91c00bade05cd21e86c01b440b91a00ba390bcd }


condition:
	$a0
}