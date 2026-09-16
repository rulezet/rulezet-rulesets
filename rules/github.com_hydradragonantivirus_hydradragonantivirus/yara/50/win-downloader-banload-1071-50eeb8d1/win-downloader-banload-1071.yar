rule Win_Downloader_Banload_1071
{
strings:
	$a0 = { cb40136aa16fb5999c71254f2aeddea6de37d0f089b608edbd29c9eb9967348a4f4561f1f84dbe9b6ed8f4fbabad91b10f87a276fcd088 }


condition:
	$a0
}