rule Win_Trojan_K_6
{
strings:
	$a0 = { 0300c606aa02e9a3ab02b440b99e0299cd21b800422bc9cd21b440b91a00baaa02cd21 }


condition:
	$a0
}