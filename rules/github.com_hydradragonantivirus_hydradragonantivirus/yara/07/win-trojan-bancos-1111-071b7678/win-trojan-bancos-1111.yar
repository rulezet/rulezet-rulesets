rule Win_Trojan_Bancos_1111
{
strings:
	$a0 = { 8006a3de61642057b1c3d1f696723c148a7f96b4df1ee19ba712ba7f42e46c247d8fbcbae2431ebdac38cd82c39dbde6802bd5a840cb01ca12c3a82846f025866fffd89abc02def4745ca6c8a6f4 }


condition:
	$a0
}