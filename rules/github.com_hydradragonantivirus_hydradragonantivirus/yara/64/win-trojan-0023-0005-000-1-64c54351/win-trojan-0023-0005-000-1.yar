rule Win_Trojan__0023_0005_000_1
{
strings:
	$a0 = { 558becc7460200405d5833d2b98700cd2150558becc7460200405d58ba9a10b91310cd21b8 }


condition:
	$a0
}