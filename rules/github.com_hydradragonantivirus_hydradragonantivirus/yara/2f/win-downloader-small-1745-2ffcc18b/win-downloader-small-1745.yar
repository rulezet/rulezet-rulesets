rule Win_Downloader_Small_1745
{
strings:
	$a0 = { 7a1e3a5c62bd9f742e8a6c644bc67702fe617c7273637665ea697576cea36d8f62af2f7dbfb66764b22936355133756e33 }


condition:
	$a0
}