rule _PolyCrypt_PE__214b215__JLab_Software_Creations_hsigned_
{
	meta:
		description = "PolyCrypt PE - 2.1.4b/2.1.5 -> JLab Software Creations (h-signed)"
	strings:
		$0 = {50 6F 6C 79 43 72 79 70 74 20 50 45 20 28 63 29 20 32 30 30 34 2D 32 30 30 35 2C 20 4A 4C 61 62 53 6F 66 74 77 61 72 65 2E 00 50 00 43 00 50 00 45}
	condition:
		$0
}