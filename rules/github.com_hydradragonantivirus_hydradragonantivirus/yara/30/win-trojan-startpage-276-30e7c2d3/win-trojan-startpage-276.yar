rule Win_Trojan_Startpage_276
{
strings:
	$a0 = { 6a496a626c0b3cede4700d46d6d958495805d474fbadeb53c1cc00bc4d02203a204d61063396eb5c240f20109b0cc3faaeadb665bf702e657865975d77fd9b1b6874 }


condition:
	$a0
}