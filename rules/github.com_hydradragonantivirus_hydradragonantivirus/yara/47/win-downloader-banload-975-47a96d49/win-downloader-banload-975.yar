rule Win_Downloader_Banload_975
{
strings:
	$a0 = { 739a33af5cfc5e2e349ed15a3d43e3eca0d2bc9427c24cc39a1e15880fbcbd7d9b5d8ec9272e9d7c6125176495bc99a6ceedcfa10630d90e54b8f3455e83d794cb8712b191e51fe4b282b4e85b89cd71 }


condition:
	$a0
}