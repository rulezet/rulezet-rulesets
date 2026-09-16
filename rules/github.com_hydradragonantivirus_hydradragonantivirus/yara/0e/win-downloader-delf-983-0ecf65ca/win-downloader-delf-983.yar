rule Win_Downloader_Delf_983
{
strings:
	$a0 = { 37232d818a9f064579e77baeb85886daf1d90e7b1ad4f890c505ffad307ca64b8f97852a95e49eed56d86c3ea5e60e24daa9c65fec63bdec5459292e783400f545e132b6f48c }


condition:
	$a0
}