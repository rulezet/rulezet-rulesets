rule Win_Trojan_Joe_1
{
strings:
	$a0 = { 04b93004800504474975f9e4fcfc597de914fdf689a204fdb8fafbf789924301b016c91dbbfcfdb500fc89b200fd }


condition:
	$a0
}