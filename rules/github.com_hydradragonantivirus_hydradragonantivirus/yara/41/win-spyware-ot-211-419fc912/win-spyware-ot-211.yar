rule Win_Spyware_ot_211
{
strings:
	$a0 = { be12d65e9fb5ee0667ce7033fbc7749a37630471c20e7ba5a9313a1bb3c6fdaf52d089218a69aee3bd127b2c6da4b0cee68effe2e342c08f702be45233678febfd3d78e4d02aca8bd933fd7c }


condition:
	$a0
}