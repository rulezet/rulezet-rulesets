rule Win_Trojan_Remember_1
{
strings:
	$a0 = { 030089868b05b440b9fd048d960501cd21b8004233c999cd21b440b905008d968a05cd21b801 }


condition:
	$a0
}