rule Win_Trojan_Slovakia_13
{
strings:
	$a0 = { 2eb509fb98b32933f690998bf99ff8b2ad56b4eff9570e525d75001f5058fc5058740075008a05b6c03004 }


condition:
	$a0
}