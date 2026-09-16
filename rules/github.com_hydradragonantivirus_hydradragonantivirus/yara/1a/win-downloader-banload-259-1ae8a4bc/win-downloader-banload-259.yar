rule Win_Downloader_Banload_259
{
strings:
	$a0 = { f0970b7b0cbfe74a813cc6aa41324d583cc0d98400393cf2d5cb06891a6ec0ec302fbde40bd1931f889f25cf13acf838f0a4255db014ce9306749d1a9ef5cfaf2f6c25d7d25507ea022d96ab56fd }


condition:
	$a0
}