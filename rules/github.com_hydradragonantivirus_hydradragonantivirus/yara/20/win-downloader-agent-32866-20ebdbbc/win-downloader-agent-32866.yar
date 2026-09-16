rule Win_Downloader_Agent_32866
{
strings:
	$a0 = { cbfc66a51a4af0bc62f6d90459b57e16e61ab77fcd9ff104cca0b2fe88d50290b6251f8d86c4d322f1aaf8f047a37f7956ff761abaf9dcf138c0b3590299 }


condition:
	$a0
}