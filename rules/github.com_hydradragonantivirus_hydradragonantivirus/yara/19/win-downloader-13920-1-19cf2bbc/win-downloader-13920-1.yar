rule Win_Downloader_13920_1
{
strings:
	$a0 = { b27044397244483532b8e2d850d6865bdfb6314cfa65aa24aeef0f1a8559d82eb952ef3cfa82f8fdb1d5af9a4f1f6589c9868276d1a42ac2b32c5a5c389940de }


condition:
	$a0
}