rule Win_Downloader_Zlob_1741
{
strings:
	$a0 = { 843bc3815a3dd18f252e8dd5e1ca927a42f4421ec5f709cab9db3531683927d098c379ac2062c162ed2124a62b3c194dc8ec1fde3ec089ca938216ae7ea7e15d84de1c50f77c9c01e9cd74e0147d }


condition:
	$a0
}