rule Win_Downloader_107815_1
{
strings:
	$a0 = { 283e00000a6f3f00000a6f4000000a2819 }

	$a1 = { 027b4f0000046f7000000a7e01 }

	$a2 = { 7e6c00000a723f050070176f6d }

	$a3 = { 1f25282c00000a0b070707725d0300706f }


condition:
	$a0 and $a1 and $a2 and $a3
}