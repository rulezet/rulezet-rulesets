rule Win_Downloader_13402_1
{
strings:
	$a0 = { b854224500e86e51fdff33d2a1fc5b4500e8367effff33d2b8?0224500e852ffffffba??224500b8????4500e8a3feffff84c0740c33d2b8??224500e833ffffff }


condition:
	$a0
}