rule Win_Downloader_Agent_34522
{
strings:
	$a0 = { 5368656c6c[0-32]4b696c6c20737a46696c654c6f63616c202620225c74656d702e65786522 }


condition:
	$a0
}