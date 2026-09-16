rule Win_Trojan_BAT_104
{
strings:
	$a0 = { 5c6c696d65776972655c7368617265645c736c[0-16]742e6d70332e626174203e6e756c }


condition:
	$a0
}