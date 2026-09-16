rule Win_Trojan_Massaker_1
{
strings:
	$a0 = { 4c12a5df15019f43611bbc8cff6c6c6261636b495073c3cc31fc69ffffffff19368f0f80dd48a915ea51438ce951e4a9 }


condition:
	$a0
}