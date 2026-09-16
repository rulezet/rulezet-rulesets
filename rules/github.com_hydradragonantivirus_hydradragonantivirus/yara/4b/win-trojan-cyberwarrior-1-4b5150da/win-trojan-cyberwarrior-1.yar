rule Win_Trojan_Cyberwarrior_1
{
strings:
	$a0 = { 21b4408d96d501b90500cd21b8024233c999cd21b440b9db008d960501cd21b801573e8b8efa01 }


condition:
	$a0
}