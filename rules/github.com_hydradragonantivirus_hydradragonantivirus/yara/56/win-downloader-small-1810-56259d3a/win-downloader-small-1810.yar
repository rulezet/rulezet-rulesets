rule Win_Downloader_Small_1810
{
strings:
	$a0 = { 687488703a2fe277cf022eee64436e3231bd0f8174fbf41418785f116c206e66a73dcf433a5c62d7b3742ef16c64 }


condition:
	$a0
}