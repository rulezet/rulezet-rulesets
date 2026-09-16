rule Win_Spyware_Banker_2575
{
strings:
	$a0 = { 0ce9d7202afe0051820ac66ed5ada905ee058bf35da8b7fc2efdade0236b472331f90c8728aaff580dc7255421f2ba9dc0a688d124015d5914140b1982efd0e248decc96bcdeae8dc4731c0073937f4d }


condition:
	$a0
}