rule Win_Downloader_Delf_1092
{
strings:
	$a0 = { 9dbf65dad397efab24bc5ccb35dc188301d73cb2214830f23ede924fa87db57dbde9a77dc1fefd9857d6edf19e5851af1ba9746b945921388faea9aae0cce6a0e1d6f63f8439f83cbd5ae8b147515498 }


condition:
	$a0
}