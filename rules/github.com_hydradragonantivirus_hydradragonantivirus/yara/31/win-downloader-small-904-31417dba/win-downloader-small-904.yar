rule Win_Downloader_Small_904
{
strings:
	$a0 = { 1c001f1bd6fe3bfc7974696d65841f633a5c72652e10f2932f4b0f687461446f63758bfa2dfa6e7473 }


condition:
	$a0
}