rule mime_mso
{
meta:
    comment = "mime mso detection"
    ref = "http://blog.malwaretracker.com/2015/03/return-of-mime-mso-now-with-macros.html"
    author = "@mwtracker"
strings:
	$a="application/x-mso"
	$b="MIME-Version"
	$c="ocxstg001.mso"
	$d="?mso-application"
condition:
	$a and $b or $c or $d
}