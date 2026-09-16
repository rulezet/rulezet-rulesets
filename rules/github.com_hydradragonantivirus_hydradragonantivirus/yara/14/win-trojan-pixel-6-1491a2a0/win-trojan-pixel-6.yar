rule Win_Trojan_Pixel_6
{
strings:
	$a0 = { b2b97900f614e2fc0e8cc880c4108ed8b41aba18f952cd21b44e1eb1200e1fba7301cd211fba36f9723ab8023dcd2193 }


condition:
	$a0
}