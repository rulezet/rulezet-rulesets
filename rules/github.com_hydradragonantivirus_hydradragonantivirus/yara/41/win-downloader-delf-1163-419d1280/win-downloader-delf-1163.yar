rule Win_Downloader_Delf_1163
{
strings:
	$a0 = { d00617aad4e8be8917e3002cd4005dd21f2a23df3e787fbbb8746ce7b5a9c3f37188bc9f917ceacdfcc5e8f636b65403dd6c42e2cc85ab12a8278d45efe428155e2123401e0986a6e67368e4d0fa412f53 }


condition:
	$a0
}