rule mhtml
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Word/Excel MHTML file format detection"
	strings:
		$str1 = "MIME-Version:"
		$str2 = "Content-Location:"
		$email_str1 = "From:"
		$email_str2 = "Subject:"
	condition:
		all of ($str*) and not any of ($email_str*)
}