rule Win_Spyware_Banker_1367
{
strings:
	$a0 = { bbcb8c966d2be2d4fd2717efce863b036d95d6ff823cf08c5f26f0fa4c039827cc2e2b5aab5e6fe9954f955f424d03b4cbbac759d7a77875b4ec839fec2a102aceb90bf0 }


condition:
	$a0
}