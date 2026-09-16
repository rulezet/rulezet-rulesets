rule Win_Downloader_VB_394
{
strings:
	$a0 = { 05f4c96c638ce1305ea8846e549daa7747b0ec76915d9f10db2d2b6b6b861bd1d944880b38b691318fab3e63991a3ba76924b34c23b3b6ca6c9efd98c11b3c7735 }


condition:
	$a0
}