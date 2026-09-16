rule Win_Trojan_ARCV_13
{
strings:
	$a0 = { bb18002e812f522943434275f63a2a5286d316652a702f60377130dfe7232bdfdf2b2bf7cef7cedfbf472d06441f4b0a4e87f673a9 }


condition:
	$a0
}