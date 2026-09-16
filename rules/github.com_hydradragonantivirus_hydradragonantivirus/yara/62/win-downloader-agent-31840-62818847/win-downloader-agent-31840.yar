rule Win_Downloader_Agent_31840
{
strings:
	$a0 = { e9a98c599e4b1716f0be49ef6f95e08e357ddbbe5bd8f0e14984f821453bfe4e8da5862693dca07fa89d66fe12fbfcf9dbda2084c9febbe08380668316f3caaa216b540f380940bdbd2476 }


condition:
	$a0
}