rule Win_Downloader_Small_3470
{
strings:
	$a0 = { 9ded35bd832cfd4f9808f54d174bfaa798d17940a880a393bd81ff0b6004babb23e3427721f65677d64c995b49b6bbcbfd0699b4c5cf1393e3d9d2a8f715af8d5b8d39964b704133af1b4c2d5f76 }


condition:
	$a0
}