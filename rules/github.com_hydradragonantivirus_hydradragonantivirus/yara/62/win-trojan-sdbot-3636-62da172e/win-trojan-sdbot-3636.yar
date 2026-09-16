rule Win_Trojan_SdBot_3636
{
strings:
	$a0 = { 6babc3589c6150d74dc36d6efde0057fa6d70cdc6e3135a39f76c8493741efb5048e7f69558a6b6d6e00d6188f2297fd5dcd7d640ccc5c2e229a6ebe2f5988e7d77f3a414f28a9ba63d6786a885c }


condition:
	$a0
}