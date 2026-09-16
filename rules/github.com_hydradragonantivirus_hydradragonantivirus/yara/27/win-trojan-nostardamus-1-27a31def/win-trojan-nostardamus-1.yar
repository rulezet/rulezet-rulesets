rule Win_Trojan_Nostardamus_1
{
strings:
	$a0 = { 3424d63750ebfa31e90b5619ca34f6677835dd6dfea5356da8a628be8537e90c5619b4347ff835fe }


condition:
	$a0
}