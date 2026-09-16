rule excel_xml
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Excel XML file format detection"
	strings:
		$header = "<?xml"
		$str = "<?mso-application progid=\"Excel.Sheet\"?>"
	condition:
	   $header at 0 and $str
}