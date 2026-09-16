rule Win_Trojan_Vundo_16
{
strings:
	$a0 = { 60e8ec1d000092636019debf8cd5eadb7851b61d }


condition:
	$a0
}