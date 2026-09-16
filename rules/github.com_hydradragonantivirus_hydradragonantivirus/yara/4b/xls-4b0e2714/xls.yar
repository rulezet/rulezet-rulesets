rule xls
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Excel 2003 file format detection"
	strings:
		$header = { D0 CF 11 E0 A1 B1 1A E1 }
		$str1 = "Microsoft Excel"
		$str2 = "Excel.Sheet.8"
	condition:
	   $header at 0 and any of ($str*) 
}