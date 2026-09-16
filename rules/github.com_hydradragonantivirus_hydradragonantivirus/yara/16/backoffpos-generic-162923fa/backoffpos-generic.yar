rule BackOffPOS_GENERIC
{
meta:
	description = "BackoffPOS generic catcher for known strings"
	in_the_wild = true

strings:
$a = "Update"
$b = "Terminate"
$d = "Uninstall"
$e = "Download"
$f = "Run"
$g = "Upload"
$h = "KeyLogs"
$i = "Password"
$j = "USERNAME"
$k = "[Enter]"
$l = "Log"

condition:

all of them

}