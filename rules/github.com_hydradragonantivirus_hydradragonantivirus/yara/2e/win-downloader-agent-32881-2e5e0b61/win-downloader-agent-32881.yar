rule Win_Downloader_Agent_32881
{
strings:
	$a0 = { 971e2daa9fb297a86b070f5afd498bfafe5647e95d805d220c02d23f1748cf1daf3cf74b1c87011134d65b6767110aca3aae834fa2c89c799c33bd9c4262 }


condition:
	$a0
}