rule Win_Trojan_Beer_6
{
strings:
	$a0 = { fa9d58595bc3e8e2ffb440b9990cba03012bca8b1eb20ce8ef00e8ceffc3b003cf }


condition:
	$a0
}