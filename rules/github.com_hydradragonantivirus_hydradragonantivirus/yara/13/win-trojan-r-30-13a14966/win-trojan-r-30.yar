rule Win_Trojan_R_30
{
strings:
	$a0 = { 16038dbe0a01b9060131354747e2fac3e8eaffb94802cd21e8e2ffc3e800008bfc368b2d81 }


condition:
	$a0
}