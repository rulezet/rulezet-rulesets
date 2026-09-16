rule Win_Trojan_Bancos_1786
{
strings:
	$a0 = { 2fcfbd5ddc595f4a1ab5f6d77388a28fbfc3c26d50d1fa2fe293a5a68d4820449ab0bd899c9c664e3056468db2b6675b2868ff989f17913d98128bcfe811d1c39ffeb9665d1b }


condition:
	$a0
}