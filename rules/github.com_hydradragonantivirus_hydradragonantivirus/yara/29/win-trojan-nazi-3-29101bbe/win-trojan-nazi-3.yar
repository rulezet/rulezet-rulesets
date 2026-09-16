rule Win_Trojan_Nazi_3
{
strings:
	$a0 = { a66702dc5c63b306ac63ed4b3497d83c9b03bdd148bd3ef07bac049701e6c9fc086217a44950 }


condition:
	$a0
}