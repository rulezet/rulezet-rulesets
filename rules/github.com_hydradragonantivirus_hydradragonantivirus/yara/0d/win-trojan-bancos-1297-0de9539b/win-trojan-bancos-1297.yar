rule Win_Trojan_Bancos_1297
{
strings:
	$a0 = { d61f90968eb6a2babb663a3600f3afe5f6fb510d4713f8e21edbe9b1c78e8cbad20edf4ff978d0667f3b50a9ea5df5c7f087ab5b8705e7108be879fdfbf9ca45bede2d9dbb357a3d1a772dded5a3721c74ae737c }


condition:
	$a0
}