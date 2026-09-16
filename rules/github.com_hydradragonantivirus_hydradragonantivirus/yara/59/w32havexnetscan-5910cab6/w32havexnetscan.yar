rule W32HavexNetscan
{
	meta:
		description = "Havex.Netscan search based on temp file & ports"
		in_the_wild = true
		reference = "https://github.com/vred/yara-rule-havex-netscan/blob/master/havex-netscan.yar"
	strings:
		$file = "~tracedscn.yls" wide nocase 
			condition:
		($file)}