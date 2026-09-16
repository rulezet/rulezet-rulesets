rule Win_Trojan_Mahon_3
{
strings:
	$a0 = { 0401b440b954058d960401cd21b8004233c999cd21b440b91c008d965104cd21e8e501b43e }


condition:
	$a0
}