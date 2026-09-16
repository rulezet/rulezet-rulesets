rule Win_Trojan_Hupigon_693
{
strings:
	$a0 = { fa331cf9158c4e9cc7c8c2ba271946893e28811854be39ca056007b5c5e270cb806ad653fc801400461d578d51ee69f7c4401d45eb0b32ca157cf34a }


condition:
	$a0
}