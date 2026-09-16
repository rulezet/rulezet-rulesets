rule Win_Trojan_SdBot_3655
{
strings:
	$a0 = { 4e04336484cc41b8bcbbb0a2ca278b3f3f77228cdc0217471aaa4fc3ecec410dea0c4b1f4e86cd47e976c790ea85d9251abb87e6f3405102d709be9258db19e67353ff71c0d3541a3348fc05cfaa }


condition:
	$a0
}