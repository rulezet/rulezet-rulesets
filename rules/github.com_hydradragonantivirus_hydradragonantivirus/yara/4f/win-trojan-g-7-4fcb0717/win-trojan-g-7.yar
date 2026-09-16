rule Win_Trojan_G_7
{
strings:
	$a0 = { 6efa81ed0300061eb84144cd213d535074408cd8488ed8832e030040832e1200 }


condition:
	$a0
}