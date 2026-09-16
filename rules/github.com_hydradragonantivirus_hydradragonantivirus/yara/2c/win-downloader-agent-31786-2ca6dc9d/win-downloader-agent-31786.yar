rule Win_Downloader_Agent_31786
{
strings:
	$a0 = { 73325f33320a002dffffcd17c954454d50687474703a2f2f75702e6d6564626f642efdd7feee636f6d0d2f63616c632e623e }


condition:
	$a0
}