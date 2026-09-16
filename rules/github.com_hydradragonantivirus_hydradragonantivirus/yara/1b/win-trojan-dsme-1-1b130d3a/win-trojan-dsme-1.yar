rule Win_Trojan_DSME_1
{
strings:
	$a0 = { 8bc802c08dbfb87c0952b2ffe7aeff5ab33fcc200d1e32c832d1b7ff41cc20b33fb803ffb97f00cc }


condition:
	$a0
}